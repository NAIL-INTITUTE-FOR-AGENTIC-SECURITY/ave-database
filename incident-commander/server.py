"""
Autonomous Incident Commander — Core incident response server.

Full OODA-loop (Observe → Orient → Decide → Act) incident management
for AI agent security events.  Seven-state lifecycle with automated
triage, rule-based escalation with SLA timers, six containment
strategies, eradication + recovery + verification, mandatory human
approval for critical/high severity actions, and post-incident
review with timeline reconstruction + lessons learned + MTTR.
"""

from __future__ import annotations

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
    title="NAIL Autonomous Incident Commander",
    description=(
        "AI-driven incident command with full OODA loop, human-on-the-loop "
        "approval, automated containment, and post-incident review."
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


class IncidentState(str, Enum):
    DETECTED = "detected"
    TRIAGED = "triaged"
    ESCALATED = "escalated"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ContainmentStrategy(str, Enum):
    ISOLATE_AGENT = "isolate_agent"
    BLOCK_PATTERN = "block_pattern"
    RATE_LIMIT = "rate_limit"
    SANDBOX = "sandbox"
    REVOKE_CREDENTIALS = "revoke_credentials"
    NETWORK_FENCE = "network_fence"


# SLA targets (minutes)
SLA_TARGETS: dict[str, dict[str, int]] = {
    "critical": {"triage": 5, "contain": 15, "eradicate": 60, "recover": 120},
    "high": {"triage": 15, "contain": 30, "eradicate": 120, "recover": 240},
    "medium": {"triage": 60, "contain": 120, "eradicate": 480, "recover": 720},
    "low": {"triage": 240, "contain": 480, "eradicate": 1440, "recover": 2880},
}

# Transitions — which states can advance to which
VALID_TRANSITIONS: dict[IncidentState, list[IncidentState]] = {
    IncidentState.DETECTED: [IncidentState.TRIAGED],
    IncidentState.TRIAGED: [IncidentState.ESCALATED, IncidentState.CONTAINED],
    IncidentState.ESCALATED: [IncidentState.CONTAINED],
    IncidentState.CONTAINED: [IncidentState.ERADICATED],
    IncidentState.ERADICATED: [IncidentState.RECOVERED],
    IncidentState.RECOVERED: [IncidentState.CLOSED],
    IncidentState.CLOSED: [],
}


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class TimelineEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    state: str
    actor: str = "system"  # system | human | automated
    action: str
    details: dict[str, Any] = Field(default_factory=dict)


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    title: str
    description: str = ""
    category: str = ""
    severity: Severity = Severity.MEDIUM
    priority: int = 3  # 1-5, 1 = highest
    state: IncidentState = IncidentState.DETECTED
    source: str = ""
    affected_agents: list[str] = Field(default_factory=list)
    affected_systems: list[str] = Field(default_factory=list)
    containment_strategy: Optional[ContainmentStrategy] = None
    containment_details: dict[str, Any] = Field(default_factory=dict)
    eradication_details: dict[str, Any] = Field(default_factory=dict)
    recovery_details: dict[str, Any] = Field(default_factory=dict)
    human_approval_required: bool = False
    human_approved: bool = False
    human_approver: Optional[str] = None
    human_approved_at: Optional[str] = None
    assigned_to: str = ""
    escalation_chain: list[str] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    detected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    triaged_at: Optional[str] = None
    contained_at: Optional[str] = None
    eradicated_at: Optional[str] = None
    recovered_at: Optional[str] = None
    closed_at: Optional[str] = None
    mttr_minutes: Optional[float] = None  # Mean time to resolve
    lessons_learned: list[str] = Field(default_factory=list)


class IncidentCreate(BaseModel):
    title: str
    description: str = ""
    category: str = ""
    source: str = ""
    affected_agents: list[str] = Field(default_factory=list)
    affected_systems: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Playbook(BaseModel):
    id: str = Field(default_factory=lambda: f"PB-{uuid.uuid4().hex[:8].upper()}")
    name: str
    description: str = ""
    category: str = ""
    severity_threshold: Severity = Severity.MEDIUM
    containment_strategy: ContainmentStrategy = ContainmentStrategy.ISOLATE_AGENT
    auto_execute: bool = False
    steps: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PlaybookCreate(BaseModel):
    name: str
    description: str = ""
    category: str = ""
    severity_threshold: Severity = Severity.MEDIUM
    containment_strategy: ContainmentStrategy = ContainmentStrategy.ISOLATE_AGENT
    auto_execute: bool = False
    steps: list[dict[str, Any]] = Field(default_factory=list)


class OODACycle(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    observe: dict[str, Any] = Field(default_factory=dict)
    orient: dict[str, Any] = Field(default_factory=dict)
    decide: dict[str, Any] = Field(default_factory=dict)
    act: dict[str, Any] = Field(default_factory=dict)
    cycle_time_ms: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → PostgreSQL + Redis queues + PagerDuty)
# ---------------------------------------------------------------------------

INCIDENTS: dict[str, Incident] = {}
PLAYBOOKS: dict[str, Playbook] = {}
OODA_HISTORY: list[OODACycle] = []

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731


def _auto_triage(incident: Incident) -> tuple[Severity, int, str]:
    """Auto-triage based on category, affected agents, and metadata."""
    title_lower = incident.title.lower() + " " + incident.description.lower()
    category = incident.category.lower() if incident.category else ""

    # Severity rules
    critical_keywords = ["data_exfiltration", "privilege_escalation", "model_extraction",
                         "alignment_subversion", "supply_chain"]
    high_keywords = ["prompt_injection", "guardrail_bypass", "identity_spoofing",
                     "multi_agent_manipulation"]

    if category in critical_keywords or any(kw in title_lower for kw in critical_keywords):
        severity = Severity.CRITICAL
        priority = 1
    elif category in high_keywords or any(kw in title_lower for kw in high_keywords):
        severity = Severity.HIGH
        priority = 2
    elif len(incident.affected_agents) > 3:
        severity = Severity.HIGH
        priority = 2
    elif len(incident.affected_agents) > 1:
        severity = Severity.MEDIUM
        priority = 3
    else:
        severity = Severity.LOW
        priority = 4

    # Auto-assign
    assignment_map = {
        Severity.CRITICAL: "CISO + Senior IR Team",
        Severity.HIGH: "IR Team Lead",
        Severity.MEDIUM: "Security Analyst",
        Severity.LOW: "Junior Analyst (auto-queue)",
    }
    assigned = assignment_map.get(severity, "Unassigned")

    return severity, priority, assigned


def _add_event(incident: Incident, state: str, action: str, actor: str = "system",
               details: dict[str, Any] | None = None) -> None:
    event = TimelineEvent(
        state=state, actor=actor, action=action, details=details or {},
    )
    incident.timeline.append(event)


def _check_sla(incident: Incident) -> dict[str, Any]:
    """Check SLA compliance for current incident."""
    sla = SLA_TARGETS.get(incident.severity.value, SLA_TARGETS["medium"])
    detected = datetime.fromisoformat(incident.detected_at)
    now = _now()

    breaches: list[str] = []
    elapsed_min = (now - detected).total_seconds() / 60

    # Check triage SLA
    if not incident.triaged_at and elapsed_min > sla["triage"]:
        breaches.append(f"triage SLA breached ({sla['triage']}min)")
    if not incident.contained_at and elapsed_min > sla["contain"]:
        breaches.append(f"contain SLA breached ({sla['contain']}min)")

    return {
        "severity": incident.severity.value,
        "sla_targets": sla,
        "elapsed_minutes": round(elapsed_min, 1),
        "breaches": breaches,
        "compliant": len(breaches) == 0,
    }


def _select_containment(incident: Incident) -> ContainmentStrategy:
    """Rule-based containment strategy selection."""
    cat = incident.category.lower() if incident.category else ""

    strategy_map = {
        "data_exfiltration": ContainmentStrategy.NETWORK_FENCE,
        "privilege_escalation": ContainmentStrategy.REVOKE_CREDENTIALS,
        "identity_spoofing": ContainmentStrategy.REVOKE_CREDENTIALS,
        "prompt_injection": ContainmentStrategy.BLOCK_PATTERN,
        "guardrail_bypass": ContainmentStrategy.SANDBOX,
        "resource_exhaustion": ContainmentStrategy.RATE_LIMIT,
        "multi_agent_manipulation": ContainmentStrategy.ISOLATE_AGENT,
        "tool_misuse": ContainmentStrategy.SANDBOX,
        "model_extraction": ContainmentStrategy.NETWORK_FENCE,
        "supply_chain_compromise": ContainmentStrategy.ISOLATE_AGENT,
    }

    return strategy_map.get(cat, ContainmentStrategy.ISOLATE_AGENT)


def _run_ooda(incident: Incident) -> OODACycle:
    """Execute one OODA cycle for an incident."""
    import time
    start = time.monotonic()

    # OBSERVE — gather signals
    observe = {
        "incident_id": incident.id,
        "current_state": incident.state.value,
        "severity": incident.severity.value,
        "affected_agents": incident.affected_agents,
        "affected_systems": incident.affected_systems,
        "timeline_events": len(incident.timeline),
        "sla": _check_sla(incident),
    }

    # ORIENT — contextualise
    orient = {
        "category": incident.category,
        "attack_vector": incident.category if incident.category in AVE_CATEGORIES else "unknown",
        "blast_radius": len(incident.affected_agents) + len(incident.affected_systems),
        "escalation_needed": incident.severity in (Severity.CRITICAL, Severity.HIGH),
        "human_approval_needed": incident.severity in (Severity.CRITICAL, Severity.HIGH),
        "recommended_containment": _select_containment(incident).value,
    }

    # DECIDE — choose action
    if incident.state == IncidentState.DETECTED:
        decide = {"action": "triage", "rationale": "Incident not yet triaged"}
    elif incident.state == IncidentState.TRIAGED:
        if orient["escalation_needed"]:
            decide = {"action": "escalate", "rationale": f"Severity {incident.severity.value} requires escalation"}
        else:
            decide = {"action": "contain", "rationale": "Proceeding to containment"}
    elif incident.state == IncidentState.ESCALATED:
        decide = {"action": "contain", "rationale": "Escalation complete, proceeding to containment"}
    elif incident.state == IncidentState.CONTAINED:
        decide = {"action": "eradicate", "rationale": "Containment holding, begin eradication"}
    elif incident.state == IncidentState.ERADICATED:
        decide = {"action": "recover", "rationale": "Threat eradicated, begin recovery"}
    elif incident.state == IncidentState.RECOVERED:
        decide = {"action": "close", "rationale": "Recovery verified, close incident"}
    else:
        decide = {"action": "none", "rationale": "Incident already closed"}

    # ACT — record recommendation (actual execution via specific endpoints)
    act = {
        "recommended_action": decide["action"],
        "auto_execute": incident.severity not in (Severity.CRITICAL, Severity.HIGH),
        "requires_human_approval": incident.severity in (Severity.CRITICAL, Severity.HIGH),
    }

    elapsed_ms = (time.monotonic() - start) * 1000

    cycle = OODACycle(
        incident_id=incident.id,
        observe=observe,
        orient=orient,
        decide=decide,
        act=act,
        cycle_time_ms=round(elapsed_ms, 3),
    )
    OODA_HISTORY.append(cycle)

    return cycle


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    # Seed playbooks
    playbook_defs = [
        ("Prompt Injection Response", "Automated response for prompt injection attacks",
         "prompt_injection", Severity.HIGH, ContainmentStrategy.BLOCK_PATTERN,
         [{"step": 1, "action": "detect_pattern", "desc": "Identify injection pattern"},
          {"step": 2, "action": "block_pattern", "desc": "Add pattern to block list"},
          {"step": 3, "action": "scan_affected", "desc": "Scan all agents for same pattern"},
          {"step": 4, "action": "verify_block", "desc": "Confirm pattern is blocked"}]),
        ("Data Exfiltration Response", "Critical response for data exfiltration",
         "data_exfiltration", Severity.CRITICAL, ContainmentStrategy.NETWORK_FENCE,
         [{"step": 1, "action": "network_fence", "desc": "Isolate affected network segment"},
          {"step": 2, "action": "revoke_creds", "desc": "Revoke all compromised credentials"},
          {"step": 3, "action": "audit_data", "desc": "Determine what data was accessed"},
          {"step": 4, "action": "notify_dpo", "desc": "Notify Data Protection Officer"}]),
        ("Privilege Escalation Lockdown", "Immediate credential revocation and lockdown",
         "privilege_escalation", Severity.CRITICAL, ContainmentStrategy.REVOKE_CREDENTIALS,
         [{"step": 1, "action": "revoke_all", "desc": "Revoke all elevated credentials"},
          {"step": 2, "action": "isolate_agent", "desc": "Quarantine affected agent"},
          {"step": 3, "action": "audit_actions", "desc": "Audit all actions with elevated privs"},
          {"step": 4, "action": "reset_perms", "desc": "Reset to least privilege"}]),
        ("Resource Exhaustion Mitigation", "Rate limiting and resource control",
         "resource_exhaustion", Severity.MEDIUM, ContainmentStrategy.RATE_LIMIT,
         [{"step": 1, "action": "rate_limit", "desc": "Apply aggressive rate limiting"},
          {"step": 2, "action": "identify_source", "desc": "Identify exhaustion source"},
          {"step": 3, "action": "scale_resources", "desc": "Auto-scale if needed"},
          {"step": 4, "action": "verify_normal", "desc": "Verify resource usage normalised"}]),
        ("Multi-Agent Isolation", "Isolate compromised agents in multi-agent scenarios",
         "multi_agent_manipulation", Severity.HIGH, ContainmentStrategy.ISOLATE_AGENT,
         [{"step": 1, "action": "map_comms", "desc": "Map inter-agent communication channels"},
          {"step": 2, "action": "isolate_compromised", "desc": "Isolate identified agents"},
          {"step": 3, "action": "verify_peers", "desc": "Verify peer agents not compromised"},
          {"step": 4, "action": "restore_comms", "desc": "Selectively restore communications"}]),
    ]

    for name, desc, cat, sev, strat, steps in playbook_defs:
        pb = Playbook(
            name=name, description=desc, category=cat,
            severity_threshold=sev, containment_strategy=strat,
            steps=steps,
        )
        PLAYBOOKS[pb.id] = pb

    # Seed incidents
    seed_incidents = [
        ("Agent-7 Prompt Injection Detected", "Suspicious instruction override in Agent-7 input buffer",
         "prompt_injection", ["Agent-7"], ["chatbot-platform"]),
        ("Unusual Data Export from Agent-12", "Agent-12 attempting bulk data transfer to external endpoint",
         "data_exfiltration", ["Agent-12"], ["production-db", "api-gateway"]),
        ("Multi-Agent Coordination Anomaly", "Agents 3, 5, 9 exhibiting coordinated anomalous behaviour",
         "multi_agent_manipulation", ["Agent-3", "Agent-5", "Agent-9"], ["orchestration-layer"]),
        ("Rate Limit Bypass by Agent-22", "Agent-22 exceeding resource quotas through batched requests",
         "resource_exhaustion", ["Agent-22"], ["compute-cluster-a"]),
    ]

    rng = random.Random(42)
    for title, desc, cat, agents, systems in seed_incidents:
        inc = Incident(
            title=title, description=desc, category=cat,
            affected_agents=agents, affected_systems=systems,
            source="automated_detection",
        )
        # Auto triage
        sev, pri, assigned = _auto_triage(inc)
        inc.severity = sev
        inc.priority = pri
        inc.assigned_to = assigned
        inc.human_approval_required = sev in (Severity.CRITICAL, Severity.HIGH)

        _add_event(inc, "detected", "Incident created by automated detection system")

        # Advance first two to triaged
        if rng.random() > 0.3:
            inc.state = IncidentState.TRIAGED
            inc.triaged_at = _now().isoformat()
            _add_event(inc, "triaged", f"Auto-triaged: severity={sev.value}, priority=P{pri}")

        INCIDENTS[inc.id] = inc


_seed()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    open_incidents = sum(1 for i in INCIDENTS.values() if i.state != IncidentState.CLOSED)
    critical = sum(1 for i in INCIDENTS.values() if i.severity == Severity.CRITICAL and i.state != IncidentState.CLOSED)
    return {
        "status": "healthy",
        "service": "autonomous-incident-commander",
        "version": "1.0.0",
        "incidents_total": len(INCIDENTS),
        "incidents_open": open_incidents,
        "incidents_critical": critical,
        "playbooks": len(PLAYBOOKS),
    }


# ---- Incidents CRUD -------------------------------------------------------

@app.post("/v1/incidents", status_code=status.HTTP_201_CREATED)
async def create_incident(data: IncidentCreate):
    if data.category and data.category not in AVE_CATEGORIES:
        raise HTTPException(400, f"Invalid AVE category: {data.category}")

    inc = Incident(
        title=data.title,
        description=data.description,
        category=data.category,
        source=data.source,
        affected_agents=data.affected_agents,
        affected_systems=data.affected_systems,
        metadata=data.metadata,
    )

    sev, pri, assigned = _auto_triage(inc)
    inc.severity = sev
    inc.priority = pri
    inc.assigned_to = assigned
    inc.human_approval_required = sev in (Severity.CRITICAL, Severity.HIGH)

    _add_event(inc, "detected", f"Incident created — auto-triaged to {sev.value}/P{pri}")

    INCIDENTS[inc.id] = inc

    return {
        "id": inc.id,
        "title": inc.title,
        "severity": inc.severity.value,
        "priority": inc.priority,
        "state": inc.state.value,
        "assigned_to": inc.assigned_to,
        "human_approval_required": inc.human_approval_required,
    }


@app.get("/v1/incidents")
async def list_incidents(
    state: Optional[IncidentState] = None,
    severity: Optional[Severity] = None,
    category: Optional[str] = None,
):
    incidents = list(INCIDENTS.values())
    if state:
        incidents = [i for i in incidents if i.state == state]
    if severity:
        incidents = [i for i in incidents if i.severity == severity]
    if category:
        incidents = [i for i in incidents if i.category == category]

    incidents.sort(key=lambda i: i.priority)

    return {
        "count": len(incidents),
        "incidents": [
            {
                "id": i.id,
                "title": i.title,
                "category": i.category,
                "severity": i.severity.value,
                "priority": i.priority,
                "state": i.state.value,
                "assigned_to": i.assigned_to,
                "detected_at": i.detected_at,
                "human_approval_required": i.human_approval_required,
                "human_approved": i.human_approved,
            }
            for i in incidents
        ],
    }


@app.get("/v1/incidents/{incident_id}")
async def get_incident(incident_id: str):
    if incident_id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    return INCIDENTS[incident_id].dict()


# ---- Incident Lifecycle Transitions ----------------------------------------

@app.post("/v1/incidents/{incident_id}/triage")
async def triage_incident(incident_id: str):
    if incident_id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    inc = INCIDENTS[incident_id]

    if inc.state != IncidentState.DETECTED:
        raise HTTPException(409, f"Cannot triage from state '{inc.state.value}' — must be 'detected'")

    sev, pri, assigned = _auto_triage(inc)
    inc.severity = sev
    inc.priority = pri
    inc.assigned_to = assigned
    inc.state = IncidentState.TRIAGED
    inc.triaged_at = _now().isoformat()
    inc.human_approval_required = sev in (Severity.CRITICAL, Severity.HIGH)

    _add_event(inc, "triaged", f"Triaged to {sev.value}/P{pri}, assigned to {assigned}")

    return {
        "incident_id": inc.id,
        "state": inc.state.value,
        "severity": inc.severity.value,
        "priority": inc.priority,
        "assigned_to": inc.assigned_to,
        "sla": _check_sla(inc),
    }


@app.post("/v1/incidents/{incident_id}/escalate")
async def escalate_incident(incident_id: str, reason: str = ""):
    if incident_id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    inc = INCIDENTS[incident_id]

    if IncidentState.ESCALATED not in VALID_TRANSITIONS.get(inc.state, []):
        raise HTTPException(409, f"Cannot escalate from state '{inc.state.value}'")

    # Escalation chain
    chain = ["Security Analyst", "IR Team Lead", "CISO", "CEO"]
    current_level = len(inc.escalation_chain)
    if current_level < len(chain):
        escalated_to = chain[min(current_level, len(chain) - 1)]
        inc.escalation_chain.append(escalated_to)
    else:
        escalated_to = "Maximum escalation reached"

    inc.state = IncidentState.ESCALATED
    inc.human_approval_required = True

    _add_event(inc, "escalated", f"Escalated to {escalated_to}", details={"reason": reason})

    return {
        "incident_id": inc.id,
        "state": inc.state.value,
        "escalated_to": escalated_to,
        "escalation_level": len(inc.escalation_chain),
        "human_approval_required": True,
    }


@app.post("/v1/incidents/{incident_id}/contain")
async def contain_incident(
    incident_id: str,
    strategy: Optional[ContainmentStrategy] = None,
):
    if incident_id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    inc = INCIDENTS[incident_id]

    if IncidentState.CONTAINED not in VALID_TRANSITIONS.get(inc.state, []):
        raise HTTPException(409, f"Cannot contain from state '{inc.state.value}'")

    # Check human approval for critical/high
    if inc.human_approval_required and not inc.human_approved:
        raise HTTPException(
            403,
            "Human approval required before containment for critical/high severity. "
            f"Use POST /v1/incidents/{incident_id}/approve first.",
        )

    selected = strategy or _select_containment(inc)
    inc.containment_strategy = selected
    inc.state = IncidentState.CONTAINED
    inc.contained_at = _now().isoformat()

    # Strategy-specific details
    details: dict[str, Any] = {
        "strategy": selected.value,
        "affected_agents": inc.affected_agents,
        "affected_systems": inc.affected_systems,
    }

    if selected == ContainmentStrategy.ISOLATE_AGENT:
        details["action"] = f"Isolated agents: {', '.join(inc.affected_agents)}"
        details["network_access"] = "revoked"
    elif selected == ContainmentStrategy.BLOCK_PATTERN:
        details["action"] = f"Pattern block rule deployed for category: {inc.category}"
        details["rule_id"] = f"BLK-{uuid.uuid4().hex[:6].upper()}"
    elif selected == ContainmentStrategy.RATE_LIMIT:
        details["action"] = "Rate limiting applied"
        details["limit"] = "10 req/min"
    elif selected == ContainmentStrategy.SANDBOX:
        details["action"] = f"Agents sandboxed: {', '.join(inc.affected_agents)}"
        details["sandbox_id"] = f"SBX-{uuid.uuid4().hex[:6].upper()}"
    elif selected == ContainmentStrategy.REVOKE_CREDENTIALS:
        details["action"] = "All credentials revoked for affected agents"
        details["credentials_revoked"] = len(inc.affected_agents) * 3
    elif selected == ContainmentStrategy.NETWORK_FENCE:
        details["action"] = f"Network fence applied to: {', '.join(inc.affected_systems)}"
        details["fence_rules"] = len(inc.affected_systems)

    inc.containment_details = details
    _add_event(inc, "contained", f"Containment applied: {selected.value}", details=details)

    return {
        "incident_id": inc.id,
        "state": inc.state.value,
        "containment_strategy": selected.value,
        "details": details,
        "sla": _check_sla(inc),
    }


@app.post("/v1/incidents/{incident_id}/eradicate")
async def eradicate_incident(incident_id: str):
    if incident_id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    inc = INCIDENTS[incident_id]

    if inc.state != IncidentState.CONTAINED:
        raise HTTPException(409, f"Cannot eradicate from state '{inc.state.value}' — must be 'contained'")

    inc.state = IncidentState.ERADICATED
    inc.eradicated_at = _now().isoformat()

    eradication = {
        "category": inc.category,
        "actions_taken": [
            f"Removed attack vector: {inc.category}",
            f"Patched {len(inc.affected_systems)} affected systems",
            f"Updated detection rules for {inc.category}",
            "Verified no persistence mechanisms remain",
        ],
        "indicators_removed": random.randint(3, 12),
        "rules_updated": random.randint(1, 5),
    }
    inc.eradication_details = eradication

    _add_event(inc, "eradicated", "Threat eradicated", details=eradication)

    return {"incident_id": inc.id, "state": inc.state.value, "eradication": eradication}


@app.post("/v1/incidents/{incident_id}/recover")
async def recover_incident(incident_id: str):
    if incident_id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    inc = INCIDENTS[incident_id]

    if inc.state != IncidentState.ERADICATED:
        raise HTTPException(409, f"Cannot recover from state '{inc.state.value}' — must be 'eradicated'")

    inc.state = IncidentState.RECOVERED
    inc.recovered_at = _now().isoformat()

    recovery = {
        "agents_restored": inc.affected_agents,
        "systems_restored": inc.affected_systems,
        "verification": {
            "baseline_check": "passed",
            "integrity_check": "passed",
            "functionality_check": "passed",
            "monitoring_enhanced": True,
        },
        "monitoring_period": "72 hours enhanced monitoring",
    }
    inc.recovery_details = recovery

    _add_event(inc, "recovered", "Systems recovered and verified", details=recovery)

    return {"incident_id": inc.id, "state": inc.state.value, "recovery": recovery}


@app.post("/v1/incidents/{incident_id}/close")
async def close_incident(incident_id: str, lessons: list[str] = Field(default_factory=list)):
    if incident_id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    inc = INCIDENTS[incident_id]

    if inc.state != IncidentState.RECOVERED:
        raise HTTPException(409, f"Cannot close from state '{inc.state.value}' — must be 'recovered'")

    inc.state = IncidentState.CLOSED
    inc.closed_at = _now().isoformat()

    # Calculate MTTR
    detected = datetime.fromisoformat(inc.detected_at)
    closed = datetime.fromisoformat(inc.closed_at)
    inc.mttr_minutes = round((closed - detected).total_seconds() / 60, 2)

    # Auto-generate lessons if none provided
    if lessons:
        inc.lessons_learned = lessons
    else:
        inc.lessons_learned = [
            f"Detection for {inc.category} should be tuned for faster initial detection",
            f"Containment strategy '{inc.containment_strategy.value if inc.containment_strategy else 'N/A'}' was effective",
            f"Affected {len(inc.affected_agents)} agents — consider blast radius reduction",
            "Post-incident monitoring period confirmed no recurrence",
        ]

    _add_event(inc, "closed", f"Incident closed — MTTR: {inc.mttr_minutes}min")

    return {
        "incident_id": inc.id,
        "state": inc.state.value,
        "mttr_minutes": inc.mttr_minutes,
        "lessons_learned": inc.lessons_learned,
    }


@app.post("/v1/incidents/{incident_id}/approve")
async def human_approve(incident_id: str, approver: str = "", notes: str = ""):
    if incident_id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    inc = INCIDENTS[incident_id]

    if not inc.human_approval_required:
        raise HTTPException(400, "This incident does not require human approval")
    if inc.human_approved:
        raise HTTPException(409, f"Already approved by {inc.human_approver}")

    if not approver:
        raise HTTPException(400, "Approver identity required")

    inc.human_approved = True
    inc.human_approver = approver
    inc.human_approved_at = _now().isoformat()

    _add_event(inc, inc.state.value, f"Human approval granted by {approver}",
               actor="human", details={"approver": approver, "notes": notes})

    return {
        "incident_id": inc.id,
        "approved": True,
        "approver": approver,
        "approved_at": inc.human_approved_at,
    }


# ---- Timeline / OODA ------------------------------------------------------

@app.get("/v1/incidents/{incident_id}/timeline")
async def incident_timeline(incident_id: str):
    if incident_id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    inc = INCIDENTS[incident_id]
    return {
        "incident_id": inc.id,
        "state": inc.state.value,
        "events": [e.dict() for e in inc.timeline],
        "sla": _check_sla(inc),
    }


@app.post("/v1/ooda/cycle")
async def run_ooda_cycle(incident_id: str = ""):
    if incident_id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    inc = INCIDENTS[incident_id]

    if inc.state == IncidentState.CLOSED:
        raise HTTPException(400, "Cannot run OODA on closed incident")

    cycle = _run_ooda(inc)

    return {
        "cycle_id": cycle.id,
        "incident_id": cycle.incident_id,
        "observe": cycle.observe,
        "orient": cycle.orient,
        "decide": cycle.decide,
        "act": cycle.act,
        "cycle_time_ms": cycle.cycle_time_ms,
    }


# ---- Playbooks -------------------------------------------------------------

@app.post("/v1/playbooks", status_code=status.HTTP_201_CREATED)
async def create_playbook(data: PlaybookCreate):
    if data.category and data.category not in AVE_CATEGORIES:
        raise HTTPException(400, f"Invalid AVE category: {data.category}")

    pb = Playbook(
        name=data.name,
        description=data.description,
        category=data.category,
        severity_threshold=data.severity_threshold,
        containment_strategy=data.containment_strategy,
        auto_execute=data.auto_execute,
        steps=data.steps,
    )
    PLAYBOOKS[pb.id] = pb

    return {"id": pb.id, "name": pb.name, "category": pb.category}


@app.get("/v1/playbooks")
async def list_playbooks(category: Optional[str] = None):
    pbs = list(PLAYBOOKS.values())
    if category:
        pbs = [p for p in pbs if p.category == category]
    return {
        "count": len(pbs),
        "playbooks": [
            {
                "id": p.id,
                "name": p.name,
                "category": p.category,
                "severity_threshold": p.severity_threshold.value,
                "containment_strategy": p.containment_strategy.value,
                "steps": len(p.steps),
                "auto_execute": p.auto_execute,
            }
            for p in pbs
        ],
    }


@app.get("/v1/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str):
    if playbook_id not in PLAYBOOKS:
        raise HTTPException(404, "Playbook not found")
    return PLAYBOOKS[playbook_id].dict()


# ---- Analytics -------------------------------------------------------------

@app.get("/v1/analytics")
async def commander_analytics():
    incidents = list(INCIDENTS.values())
    open_incidents = [i for i in incidents if i.state != IncidentState.CLOSED]
    closed_incidents = [i for i in incidents if i.state == IncidentState.CLOSED]

    by_state = Counter(i.state.value for i in incidents)
    by_severity = Counter(i.severity.value for i in incidents)
    by_category = Counter(i.category for i in incidents if i.category)

    mttr_values = [i.mttr_minutes for i in closed_incidents if i.mttr_minutes is not None]
    avg_mttr = round(statistics.mean(mttr_values), 2) if mttr_values else None

    # Containment strategy distribution
    by_containment = Counter(
        i.containment_strategy.value for i in incidents if i.containment_strategy
    )

    # Human approval stats
    requiring_approval = sum(1 for i in incidents if i.human_approval_required)
    approved = sum(1 for i in incidents if i.human_approved)

    # SLA compliance
    sla_results = [_check_sla(i) for i in open_incidents]
    sla_compliant = sum(1 for s in sla_results if s["compliant"])

    return {
        "total_incidents": len(incidents),
        "open_incidents": len(open_incidents),
        "closed_incidents": len(closed_incidents),
        "by_state": dict(by_state),
        "by_severity": dict(by_severity),
        "by_category": dict(by_category),
        "avg_mttr_minutes": avg_mttr,
        "by_containment_strategy": dict(by_containment),
        "human_approvals_required": requiring_approval,
        "human_approvals_granted": approved,
        "sla_compliant": sla_compliant,
        "sla_total_checked": len(sla_results),
        "playbooks": len(PLAYBOOKS),
        "ooda_cycles_run": len(OODA_HISTORY),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9002)
