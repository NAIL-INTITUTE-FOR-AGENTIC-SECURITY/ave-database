"""
Autonomous Incident Commander — Phase 21 Service 4 of 5
Port: 9503

AI-driven incident response orchestrator with playbook execution,
escalation chains, war-room coordination, real-time status tracking,
and automated post-mortem generation.
"""

from __future__ import annotations

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

class IncidentState(str, Enum):
    detected = "detected"
    triaged = "triaged"
    escalated = "escalated"
    mitigating = "mitigating"
    contained = "contained"
    resolved = "resolved"
    post_mortem = "post_mortem"


STATE_ORDER = list(IncidentState)


class Severity(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


SEVERITY_SLA_MINUTES = {"P1": 15, "P2": 60, "P3": 240, "P4": 1440}


class IncidentType(str, Enum):
    prompt_injection_incident = "prompt_injection_incident"
    data_exfiltration_incident = "data_exfiltration_incident"
    privilege_escalation_incident = "privilege_escalation_incident"
    multi_agent_compromise = "multi_agent_compromise"
    supply_chain_incident = "supply_chain_incident"
    model_extraction_incident = "model_extraction_incident"
    guardrail_bypass_incident = "guardrail_bypass_incident"
    alignment_subversion_incident = "alignment_subversion_incident"


class StepType(str, Enum):
    investigate = "investigate"
    isolate = "isolate"
    mitigate = "mitigate"
    verify = "verify"
    communicate = "communicate"
    escalate = "escalate"


class StepStatus(str, Enum):
    pending = "pending"
    in_progress = "in_progress"
    completed = "completed"
    skipped = "skipped"
    failed = "failed"


class EscalationTier(str, Enum):
    on_call = "on_call"
    team_lead = "team_lead"
    director = "director"
    ciso = "ciso"
    ceo = "ceo"


TIER_ORDER = list(EscalationTier)


class WarRoomRole(str, Enum):
    commander = "commander"
    investigator = "investigator"
    communicator = "communicator"
    scribe = "scribe"


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

class IncidentCreate(BaseModel):
    title: str
    incident_type: IncidentType
    severity: Severity = Severity.P3
    description: str = ""
    affected_services: List[str] = Field(default_factory=list)
    reporter: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentRecord(IncidentCreate):
    incident_id: str
    state: IncidentState = IncidentState.detected
    commander: str = ""
    current_escalation_tier: EscalationTier = EscalationTier.on_call
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    playbook_id: Optional[str] = None
    playbook_progress: List[Dict[str, Any]] = Field(default_factory=list)
    warroom: List[Dict[str, Any]] = Field(default_factory=list)
    post_mortem: Optional[Dict[str, Any]] = None
    created_at: str
    updated_at: str
    resolved_at: Optional[str] = None
    mttr_minutes: Optional[float] = None


class PlaybookCreate(BaseModel):
    name: str
    incident_type: IncidentType
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    description: str = ""


class PlaybookRecord(PlaybookCreate):
    playbook_id: str
    created_at: str


class EscalationChainCreate(BaseModel):
    name: str
    severity: Severity
    tiers: List[Dict[str, Any]] = Field(default_factory=list)


class EscalationChainRecord(EscalationChainCreate):
    chain_id: str
    created_at: str


class WarRoomMessage(BaseModel):
    author: str
    role: WarRoomRole = WarRoomRole.investigator
    content: str
    pinned: bool = False
    action_item: bool = False


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

incidents: Dict[str, IncidentRecord] = {}
playbooks: Dict[str, PlaybookRecord] = {}
escalation_chains: Dict[str, EscalationChainRecord] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _add_timeline(inc: IncidentRecord, event: str, detail: str = ""):
    inc.timeline.append({"event": event, "detail": detail, "timestamp": _now()})
    inc.updated_at = _now()


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Autonomous Incident Commander",
    description="Phase 21 — Incident response orchestration, playbooks, escalation, war room, post-mortems",
    version="21.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    active = sum(1 for i in incidents.values() if i.state not in (IncidentState.resolved, IncidentState.post_mortem))
    return {
        "service": "autonomous-incident-commander",
        "status": "healthy",
        "phase": 21,
        "port": 9503,
        "stats": {
            "total_incidents": len(incidents),
            "active_incidents": active,
            "playbooks": len(playbooks),
            "escalation_chains": len(escalation_chains),
        },
        "timestamp": _now(),
    }


# -- Incidents ---------------------------------------------------------------

@app.post("/v1/incidents", status_code=201)
def declare_incident(body: IncidentCreate):
    iid = f"INC-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = IncidentRecord(**body.dict(), incident_id=iid, created_at=now, updated_at=now)
    _add_timeline(record, "incident_declared", f"Severity {body.severity.value}: {body.title}")

    # Auto-triage
    record.state = IncidentState.triaged
    _add_timeline(record, "auto_triaged", f"Type: {body.incident_type.value}")

    # Auto-escalate P1/P2
    if body.severity in (Severity.P1, Severity.P2):
        record.state = IncidentState.escalated
        record.current_escalation_tier = EscalationTier.team_lead if body.severity == Severity.P2 else EscalationTier.director
        _add_timeline(record, "auto_escalated", f"Tier: {record.current_escalation_tier.value}")

    incidents[iid] = record
    return record.dict()


@app.get("/v1/incidents")
def list_incidents(
    state: Optional[IncidentState] = None,
    severity: Optional[Severity] = None,
    incident_type: Optional[IncidentType] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(incidents.values())
    if state:
        results = [i for i in results if i.state == state]
    if severity:
        results = [i for i in results if i.severity == severity]
    if incident_type:
        results = [i for i in results if i.incident_type == incident_type]
    results.sort(key=lambda i: i.created_at, reverse=True)
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
    idx = STATE_ORDER.index(inc.state)
    if idx >= len(STATE_ORDER) - 1:
        raise HTTPException(409, "Incident already at final state")
    new_state = STATE_ORDER[idx + 1]
    inc.state = new_state
    _add_timeline(inc, "state_advanced", f"-> {new_state.value}")

    if new_state == IncidentState.resolved:
        inc.resolved_at = _now()
        try:
            created = datetime.fromisoformat(inc.created_at)
            resolved = datetime.fromisoformat(inc.resolved_at)
            inc.mttr_minutes = round((resolved - created).total_seconds() / 60, 2)
        except Exception:
            pass

    return {"incident_id": inc_id, "state": inc.state.value}


# -- Playbooks ---------------------------------------------------------------

@app.post("/v1/playbooks", status_code=201)
def create_playbook(body: PlaybookCreate):
    pid = f"PB-{uuid.uuid4().hex[:12]}"
    record = PlaybookRecord(**body.dict(), playbook_id=pid, created_at=_now())
    playbooks[pid] = record
    return record.dict()


@app.get("/v1/playbooks")
def list_playbooks(incident_type: Optional[IncidentType] = None):
    results = list(playbooks.values())
    if incident_type:
        results = [p for p in results if p.incident_type == incident_type]
    return {"playbooks": [p.dict() for p in results], "total": len(results)}


@app.post("/v1/incidents/{inc_id}/execute")
def execute_playbook_step(inc_id: str, step_index: int = 0):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    inc = incidents[inc_id]
    if not inc.playbook_id or inc.playbook_id not in playbooks:
        matching = [p for p in playbooks.values() if p.incident_type == inc.incident_type]
        if not matching:
            raise HTTPException(404, "No matching playbook found")
        inc.playbook_id = matching[0].playbook_id

    pb = playbooks[inc.playbook_id]
    if step_index >= len(pb.steps):
        raise HTTPException(422, f"Step index {step_index} out of range (playbook has {len(pb.steps)} steps)")

    step = pb.steps[step_index]
    execution = {
        "step_index": step_index,
        "step_type": step.get("step_type", "unknown"),
        "description": step.get("description", ""),
        "status": "completed",
        "executed_at": _now(),
    }
    inc.playbook_progress.append(execution)
    _add_timeline(inc, "playbook_step_executed", f"Step {step_index}: {step.get('step_type', 'unknown')}")
    inc.state = IncidentState.mitigating
    return execution


# -- Escalation Chains -------------------------------------------------------

@app.post("/v1/escalation-chains", status_code=201)
def create_escalation_chain(body: EscalationChainCreate):
    cid = f"ESC-{uuid.uuid4().hex[:12]}"
    record = EscalationChainRecord(**body.dict(), chain_id=cid, created_at=_now())
    escalation_chains[cid] = record
    return record.dict()


@app.get("/v1/escalation-chains")
def list_escalation_chains():
    return {"chains": [c.dict() for c in escalation_chains.values()], "total": len(escalation_chains)}


@app.post("/v1/incidents/{inc_id}/escalate")
def escalate_incident(inc_id: str):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    inc = incidents[inc_id]
    tier_idx = TIER_ORDER.index(inc.current_escalation_tier)
    if tier_idx >= len(TIER_ORDER) - 1:
        raise HTTPException(409, "Already at highest escalation tier")
    new_tier = TIER_ORDER[tier_idx + 1]
    inc.current_escalation_tier = new_tier
    inc.state = IncidentState.escalated
    _add_timeline(inc, "escalated", f"-> {new_tier.value}")
    return {"incident_id": inc_id, "escalation_tier": new_tier.value}


# -- War Room ----------------------------------------------------------------

@app.post("/v1/incidents/{inc_id}/warroom", status_code=201)
def post_warroom_message(inc_id: str, body: WarRoomMessage):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    inc = incidents[inc_id]
    msg = {
        "message_id": f"MSG-{uuid.uuid4().hex[:8]}",
        "author": body.author,
        "role": body.role.value,
        "content": body.content,
        "pinned": body.pinned,
        "action_item": body.action_item,
        "posted_at": _now(),
    }
    inc.warroom.append(msg)
    _add_timeline(inc, "warroom_message", f"{body.role.value}: {body.content[:80]}")
    return msg


@app.get("/v1/incidents/{inc_id}/warroom")
def get_warroom(inc_id: str):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    inc = incidents[inc_id]
    pinned = [m for m in inc.warroom if m.get("pinned")]
    action_items = [m for m in inc.warroom if m.get("action_item")]
    return {
        "incident_id": inc_id,
        "messages": inc.warroom,
        "total_messages": len(inc.warroom),
        "pinned_decisions": pinned,
        "action_items": action_items,
    }


# -- Post-Mortem -------------------------------------------------------------

@app.post("/v1/incidents/{inc_id}/postmortem")
def generate_postmortem(inc_id: str):
    if inc_id not in incidents:
        raise HTTPException(404, "Incident not found")
    inc = incidents[inc_id]
    if inc.state not in (IncidentState.resolved, IncidentState.post_mortem):
        raise HTTPException(422, "Incident must be resolved before post-mortem")

    inc.state = IncidentState.post_mortem
    pinned = [m for m in inc.warroom if m.get("pinned")]
    action_items = [m for m in inc.warroom if m.get("action_item")]

    inc.post_mortem = {
        "incident_id": inc_id,
        "title": inc.title,
        "severity": inc.severity.value,
        "incident_type": inc.incident_type.value,
        "timeline_summary": [
            {"event": e["event"], "timestamp": e["timestamp"]}
            for e in inc.timeline
        ],
        "root_cause_analysis": {
            "template": "5 Whys",
            "why_1": "To be completed by incident team",
            "why_2": "",
            "why_3": "",
            "why_4": "",
            "why_5": "",
        },
        "contributing_factors": inc.affected_services,
        "mitigation_steps_taken": [
            {"step": s.get("step_type", ""), "status": s.get("status", "")}
            for s in inc.playbook_progress
        ],
        "remediation_items": [
            {"description": ai.get("content", ""), "owner": ai.get("author", ""), "deadline": "TBD"}
            for ai in action_items
        ],
        "key_decisions": [m.get("content", "") for m in pinned],
        "lessons_learned": [],
        "mttr_minutes": inc.mttr_minutes,
        "blameless": True,
        "generated_at": _now(),
    }
    _add_timeline(inc, "postmortem_generated")
    return inc.post_mortem


# -- Status Board -------------------------------------------------------------

@app.get("/v1/status-board")
def status_board():
    active = [i for i in incidents.values() if i.state not in (IncidentState.resolved, IncidentState.post_mortem)]
    resolved = [i for i in incidents.values() if i.state in (IncidentState.resolved, IncidentState.post_mortem)]

    sev_active: Dict[str, int] = defaultdict(int)
    for i in active:
        sev_active[i.severity.value] += 1

    mttrs = [i.mttr_minutes for i in resolved if i.mttr_minutes is not None]
    avg_mttr = round(sum(mttrs) / max(len(mttrs), 1), 2) if mttrs else None

    return {
        "active_incidents": len(active),
        "active_by_severity": dict(sev_active),
        "resolved_incidents": len(resolved),
        "avg_mttr_minutes": avg_mttr,
        "active_details": [
            {
                "incident_id": i.incident_id,
                "title": i.title,
                "severity": i.severity.value,
                "state": i.state.value,
                "escalation_tier": i.current_escalation_tier.value,
                "age_events": len(i.timeline),
            }
            for i in active
        ],
    }


# -- Analytics ----------------------------------------------------------------

@app.get("/v1/analytics")
def analytics():
    state_dist: Dict[str, int] = defaultdict(int)
    sev_dist: Dict[str, int] = defaultdict(int)
    type_dist: Dict[str, int] = defaultdict(int)
    for i in incidents.values():
        state_dist[i.state.value] += 1
        sev_dist[i.severity.value] += 1
        type_dist[i.incident_type.value] += 1

    mttrs = [i.mttr_minutes for i in incidents.values() if i.mttr_minutes is not None]
    return {
        "incidents": {
            "total": len(incidents),
            "state_distribution": dict(state_dist),
            "severity_distribution": dict(sev_dist),
            "type_distribution": dict(type_dist),
        },
        "mttr": {
            "avg_minutes": round(sum(mttrs) / max(len(mttrs), 1), 2) if mttrs else None,
            "min_minutes": round(min(mttrs), 2) if mttrs else None,
            "max_minutes": round(max(mttrs), 2) if mttrs else None,
            "sample_size": len(mttrs),
        },
        "playbooks": len(playbooks),
        "escalation_chains": len(escalation_chains),
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9503)
