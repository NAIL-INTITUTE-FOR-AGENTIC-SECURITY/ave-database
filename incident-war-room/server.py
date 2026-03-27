"""
Collaborative Incident War Room — Phase 24 Service 2 of 5
Port: 9801

Real-time multi-stakeholder incident coordination with role-based
channels, evidence sharing, timeline reconstruction, and cross-org
collaboration.
"""

from __future__ import annotations

import hashlib
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

class Severity(str, Enum):
    P1 = "P1-critical"
    P2 = "P2-high"
    P3 = "P3-medium"
    P4 = "P4-low"


class IncidentType(str, Enum):
    security_breach = "security_breach"
    data_leak = "data_leak"
    system_outage = "system_outage"
    policy_violation = "policy_violation"
    supply_chain = "supply_chain"
    other = "other"


class IncidentState(str, Enum):
    declared = "declared"
    triaging = "triaging"
    investigating = "investigating"
    containing = "containing"
    remediating = "remediating"
    resolved = "resolved"
    post_mortem = "post_mortem"


INCIDENT_STATES = list(IncidentState)


class ParticipantRole(str, Enum):
    commander = "commander"
    analyst = "analyst"
    responder = "responder"
    observer = "observer"
    liaison = "liaison"


class EvidenceType(str, Enum):
    log_file = "log_file"
    screenshot = "screenshot"
    memory_dump = "memory_dump"
    network_capture = "network_capture"
    config_snapshot = "config_snapshot"
    forensic_image = "forensic_image"
    other = "other"


class EvidenceClassification(str, Enum):
    public = "public"
    restricted = "restricted"
    confidential = "confidential"


class TimelineEventType(str, Enum):
    detection = "detection"
    escalation = "escalation"
    action = "action"
    communication = "communication"
    evidence = "evidence"
    resolution = "resolution"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class IncidentCreate(BaseModel):
    title: str
    description: str = ""
    severity: Severity = Severity.P3
    incident_type: IncidentType = IncidentType.other
    affected_systems: List[str] = Field(default_factory=list)
    lead_organisation: str = ""
    declared_by: str = ""


class IncidentRecord(IncidentCreate):
    incident_id: str
    state: IncidentState = IncidentState.declared
    participants: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    messages: List[Dict[str, Any]] = Field(default_factory=list)
    status_updates: List[Dict[str, Any]] = Field(default_factory=list)
    post_mortem_report: Optional[Dict[str, Any]] = None
    declared_at: str
    resolved_at: Optional[str] = None
    updated_at: str


class ParticipantAdd(BaseModel):
    name: str
    organisation: str
    role: ParticipantRole = ParticipantRole.observer
    email: str = ""


class EvidenceSubmit(BaseModel):
    title: str
    evidence_type: EvidenceType
    classification: EvidenceClassification = EvidenceClassification.restricted
    description: str = ""
    content_hash: str = ""  # SHA-256 integrity
    submitted_by: str = ""
    organisation: str = ""


class EvidenceRecord(EvidenceSubmit):
    evidence_id: str
    incident_id: str
    chain_of_custody: List[Dict[str, Any]] = Field(default_factory=list)
    submitted_at: str


class TimelineEvent(BaseModel):
    event_type: TimelineEventType
    description: str
    actor: str = ""
    organisation: str = ""


class MessagePost(BaseModel):
    sender: str
    organisation: str = ""
    role: ParticipantRole = ParticipantRole.observer
    content: str
    evidence_refs: List[str] = Field(default_factory=list)


class StatusUpdate(BaseModel):
    author: str
    summary: str
    next_steps: str = ""
    eta: str = ""


class PostMortemRequest(BaseModel):
    root_cause: str = ""
    impact_summary: str = ""
    lessons_learned: List[str] = Field(default_factory=list)
    action_items: List[str] = Field(default_factory=list)
    author: str = ""


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

incidents: Dict[str, IncidentRecord] = {}
evidence_store: Dict[str, EvidenceRecord] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _add_timeline(inc: IncidentRecord, event_type: str, desc: str, actor: str = "", org: str = ""):
    inc.timeline.append({
        "event_type": event_type,
        "description": desc,
        "actor": actor,
        "organisation": org,
        "timestamp": _now(),
    })


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Collaborative Incident War Room",
    description="Phase 24 — Real-time multi-stakeholder incident coordination with evidence and timeline",
    version="24.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    active = sum(1 for i in incidents.values() if i.state not in (IncidentState.resolved, IncidentState.post_mortem))
    return {
        "service": "collaborative-incident-war-room",
        "status": "healthy",
        "phase": 24,
        "port": 9801,
        "stats": {
            "incidents": len(incidents),
            "active": active,
            "evidence_items": len(evidence_store),
        },
        "timestamp": _now(),
    }


# -- Incidents ---------------------------------------------------------------

@app.post("/v1/incidents", status_code=201)
def declare_incident(body: IncidentCreate):
    iid = f"INC-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = IncidentRecord(**body.dict(), incident_id=iid, declared_at=now, updated_at=now)
    _add_timeline(record, "detection", f"Incident declared: {body.title}", body.declared_by, body.lead_organisation)
    incidents[iid] = record
    return record.dict()


@app.get("/v1/incidents")
def list_incidents(
    severity: Optional[Severity] = None,
    state: Optional[IncidentState] = None,
    incident_type: Optional[IncidentType] = None,
    limit: int = Query(default=50, ge=1, le=500),
):
    results = list(incidents.values())
    if severity:
        results = [i for i in results if i.severity == severity]
    if state:
        results = [i for i in results if i.state == state]
    if incident_type:
        results = [i for i in results if i.incident_type == incident_type]
    results.sort(key=lambda i: i.declared_at, reverse=True)
    return {"incidents": [i.dict() for i in results[:limit]], "total": len(results)}


@app.get("/v1/incidents/{inc_id}")
def get_incident(inc_id: str):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    return incidents[inc_id].dict()


@app.patch("/v1/incidents/{inc_id}/advance")
def advance_incident(inc_id: str):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    inc = incidents[inc_id]
    idx = INCIDENT_STATES.index(inc.state)
    if idx >= len(INCIDENT_STATES) - 1:
        raise HTTPException(409, "Incident already at final state")
    inc.state = INCIDENT_STATES[idx + 1]
    inc.updated_at = _now()
    if inc.state == IncidentState.resolved:
        inc.resolved_at = _now()
    _add_timeline(inc, "escalation", f"State advanced to {inc.state.value}")
    return {"incident_id": inc_id, "state": inc.state.value}


# -- Participants ------------------------------------------------------------

@app.post("/v1/incidents/{inc_id}/participants", status_code=201)
def add_participant(inc_id: str, body: ParticipantAdd):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    inc = incidents[inc_id]
    participant = {
        "participant_id": f"PRT-{uuid.uuid4().hex[:8]}",
        **body.dict(),
        "joined_at": _now(),
    }
    inc.participants.append(participant)
    inc.updated_at = _now()
    _add_timeline(inc, "communication", f"{body.name} ({body.role.value}) from {body.organisation} joined", body.name, body.organisation)
    return participant


# -- Evidence ----------------------------------------------------------------

@app.post("/v1/incidents/{inc_id}/evidence", status_code=201)
def submit_evidence(inc_id: str, body: EvidenceSubmit):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    eid = f"EV-{uuid.uuid4().hex[:12]}"
    if not body.content_hash:
        body.content_hash = hashlib.sha256(f"{body.title}{_now()}".encode()).hexdigest()
    record = EvidenceRecord(
        **body.dict(), evidence_id=eid, incident_id=inc_id, submitted_at=_now(),
    )
    record.chain_of_custody.append({
        "action": "submitted",
        "actor": body.submitted_by,
        "organisation": body.organisation,
        "timestamp": _now(),
    })
    evidence_store[eid] = record
    incidents[inc_id].evidence_ids.append(eid)
    incidents[inc_id].updated_at = _now()
    _add_timeline(incidents[inc_id], "evidence", f"Evidence submitted: {body.title}", body.submitted_by, body.organisation)
    return record.dict()


@app.get("/v1/incidents/{inc_id}/evidence")
def list_evidence(inc_id: str):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    items = [evidence_store[eid].dict() for eid in incidents[inc_id].evidence_ids if eid in evidence_store]
    return {"evidence": items, "total": len(items)}


# -- Timeline ----------------------------------------------------------------

@app.post("/v1/incidents/{inc_id}/timeline", status_code=201)
def add_timeline_event(inc_id: str, body: TimelineEvent):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    _add_timeline(incidents[inc_id], body.event_type.value, body.description, body.actor, body.organisation)
    incidents[inc_id].updated_at = _now()
    return {"incident_id": inc_id, "timeline_count": len(incidents[inc_id].timeline)}


@app.get("/v1/incidents/{inc_id}/timeline")
def get_timeline(inc_id: str):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    return {"incident_id": inc_id, "timeline": incidents[inc_id].timeline}


# -- Messages ----------------------------------------------------------------

@app.post("/v1/incidents/{inc_id}/messages", status_code=201)
def post_message(inc_id: str, body: MessagePost):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    msg = {
        "message_id": f"MSG-{uuid.uuid4().hex[:8]}",
        **body.dict(),
        "posted_at": _now(),
    }
    incidents[inc_id].messages.append(msg)
    incidents[inc_id].updated_at = _now()
    return msg


@app.get("/v1/incidents/{inc_id}/messages")
def get_messages(inc_id: str, role: Optional[ParticipantRole] = None):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    msgs = incidents[inc_id].messages
    if role:
        msgs = [m for m in msgs if m.get("role") == role.value]
    return {"messages": msgs, "total": len(msgs)}


# -- Status Updates ----------------------------------------------------------

@app.post("/v1/incidents/{inc_id}/status", status_code=201)
def post_status(inc_id: str, body: StatusUpdate):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    update = {**body.dict(), "posted_at": _now()}
    incidents[inc_id].status_updates.append(update)
    incidents[inc_id].updated_at = _now()
    _add_timeline(incidents[inc_id], "communication", f"Status update by {body.author}: {body.summary}", body.author)
    return update


# -- Post-Mortem -------------------------------------------------------------

@app.post("/v1/incidents/{inc_id}/post-mortem")
def generate_post_mortem(inc_id: str, body: PostMortemRequest):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    inc = incidents[inc_id]

    # Auto-populate from incident data
    timeline_summary = [
        f"[{e['timestamp']}] {e['event_type']}: {e['description']}"
        for e in inc.timeline[-20:]
    ]
    evidence_summary = [
        {"id": eid, "title": evidence_store[eid].title, "type": evidence_store[eid].evidence_type.value}
        for eid in inc.evidence_ids if eid in evidence_store
    ]

    report = {
        "incident_id": inc_id,
        "title": inc.title,
        "severity": inc.severity.value,
        "incident_type": inc.incident_type.value,
        "root_cause": body.root_cause or "To be determined",
        "impact_summary": body.impact_summary or f"Affected systems: {', '.join(inc.affected_systems) or 'N/A'}",
        "timeline_summary": timeline_summary,
        "evidence_count": len(evidence_summary),
        "evidence_summary": evidence_summary,
        "participants": len(inc.participants),
        "organisations_involved": list(set(p.get("organisation", "") for p in inc.participants)),
        "lessons_learned": body.lessons_learned,
        "action_items": body.action_items,
        "duration_info": {
            "declared_at": inc.declared_at,
            "resolved_at": inc.resolved_at,
        },
        "generated_at": _now(),
        "author": body.author,
    }
    inc.post_mortem_report = report
    inc.updated_at = _now()
    if inc.state != IncidentState.post_mortem:
        inc.state = IncidentState.post_mortem
    return report


# -- Analytics ----------------------------------------------------------------

@app.get("/v1/analytics")
def analytics():
    sev_dist: Dict[str, int] = defaultdict(int)
    type_dist: Dict[str, int] = defaultdict(int)
    state_dist: Dict[str, int] = defaultdict(int)
    org_dist: Dict[str, int] = defaultdict(int)
    for inc in incidents.values():
        sev_dist[inc.severity.value] += 1
        type_dist[inc.incident_type.value] += 1
        state_dist[inc.state.value] += 1
        for p in inc.participants:
            org_dist[p.get("organisation", "unknown")] += 1

    resolved = [i for i in incidents.values() if i.resolved_at and i.declared_at]
    ev_types: Dict[str, int] = defaultdict(int)
    for ev in evidence_store.values():
        ev_types[ev.evidence_type.value] += 1

    return {
        "incidents": {
            "total": len(incidents),
            "severity_distribution": dict(sev_dist),
            "type_distribution": dict(type_dist),
            "state_distribution": dict(state_dist),
            "with_post_mortem": sum(1 for i in incidents.values() if i.post_mortem_report),
        },
        "participants": {
            "total": sum(len(i.participants) for i in incidents.values()),
            "organisation_distribution": dict(org_dist),
        },
        "evidence": {
            "total": len(evidence_store),
            "type_distribution": dict(ev_types),
        },
        "messages": {
            "total": sum(len(i.messages) for i in incidents.values()),
        },
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9801)
