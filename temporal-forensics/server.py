"""
Temporal Attack Forensics — Core forensics server.

Time-series reconstruction engine for multi-stage attacks spanning
hours/days across agent ecosystems.  Captures, indexes, and analyses
security events to reconstruct full chronology, build temporal
attack graphs, identify causal chains, recognise recurring temporal
patterns, and project likely future attack timelines.
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
    title="NAIL Temporal Attack Forensics",
    description=(
        "Time-series attack reconstruction — timeline assembly, causal "
        "chain analysis, pattern matching, and predictive projection."
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
# Constants / Enums
# ---------------------------------------------------------------------------

AVE_CATEGORIES = [
    "prompt_injection", "tool_misuse", "memory_poisoning", "goal_hijacking",
    "identity_spoofing", "privilege_escalation", "data_exfiltration",
    "resource_exhaustion", "multi_agent_manipulation", "context_overflow",
    "guardrail_bypass", "output_manipulation", "supply_chain_compromise",
    "model_extraction", "reward_hacking", "capability_elicitation",
    "alignment_subversion", "delegation_abuse",
]

KILL_CHAIN_STAGES = [
    "reconnaissance", "weaponisation", "delivery", "exploitation",
    "installation", "command_and_control", "objectives",
]


class EventSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PatternType(str, Enum):
    KILL_CHAIN = "kill_chain"
    SLOW_AND_LOW = "slow_and_low"
    BURST = "burst"
    OSCILLATING = "oscillating"
    DORMANT_THEN_ACTIVE = "dormant_then_active"
    COORDINATED = "coordinated"


class TimelineStatus(str, Enum):
    PARTIAL = "partial"
    COMPLETE = "complete"
    ANALYSED = "analysed"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class SecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_agent: str = ""
    target_agent: str = ""
    system: str = ""
    category: str = ""
    severity: EventSeverity = EventSeverity.MEDIUM
    stage: str = ""  # Kill chain stage
    action: str = ""
    outcome: str = ""  # success, blocked, partial
    indicators: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EventCreate(BaseModel):
    source_agent: str = ""
    target_agent: str = ""
    system: str = ""
    category: str = ""
    severity: EventSeverity = EventSeverity.MEDIUM
    stage: str = ""
    action: str = ""
    outcome: str = ""
    indicators: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ForensicTimeline(BaseModel):
    id: str = Field(default_factory=lambda: f"TL-{uuid.uuid4().hex[:8].upper()}")
    incident_id: str = ""
    title: str = ""
    status: TimelineStatus = TimelineStatus.PARTIAL
    events: list[str] = Field(default_factory=list)  # Event IDs in chronological order
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_minutes: float = 0.0
    agents_involved: list[str] = Field(default_factory=list)
    systems_involved: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    gaps_detected: list[dict[str, Any]] = Field(default_factory=list)
    causal_chain: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TimelineCreate(BaseModel):
    incident_id: str = ""
    title: str = ""
    event_ids: list[str] = Field(default_factory=list)
    time_range_start: Optional[str] = None
    time_range_end: Optional[str] = None
    agent_filter: list[str] = Field(default_factory=list)
    category_filter: list[str] = Field(default_factory=list)


class TemporalPattern(BaseModel):
    id: str = Field(default_factory=lambda: f"PAT-{uuid.uuid4().hex[:8].upper()}")
    name: str
    pattern_type: PatternType
    description: str = ""
    stage_sequence: list[str] = Field(default_factory=list)
    min_duration_minutes: float = 0.0
    max_duration_minutes: float = float("inf")
    min_events: int = 2
    category: str = ""
    indicators: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PatternCreate(BaseModel):
    name: str
    pattern_type: PatternType
    description: str = ""
    stage_sequence: list[str] = Field(default_factory=list)
    min_duration_minutes: float = 0.0
    max_duration_minutes: float = 99999.0
    min_events: int = 2
    category: str = ""
    indicators: list[str] = Field(default_factory=list)


class PredictionResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timeline_id: str
    current_stage: str
    predicted_next_stages: list[dict[str, Any]] = Field(default_factory=list)
    estimated_time_to_next: float = 0.0  # minutes
    confidence: float = 0.0
    risk_level: str = ""
    predicted_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → Kafka + ClickHouse + Neo4j)
# ---------------------------------------------------------------------------

EVENTS: dict[str, SecurityEvent] = {}
TIMELINES: dict[str, ForensicTimeline] = {}
PATTERNS: dict[str, TemporalPattern] = {}
PREDICTIONS: list[PredictionResult] = []
CORRELATIONS: list[dict[str, Any]] = []

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731
_rng = random.Random(42)


def _reconstruct_timeline(event_ids: list[str], title: str = "",
                          incident_id: str = "") -> ForensicTimeline:
    """Assemble events into a chronological timeline with gap detection."""
    events = [EVENTS[eid] for eid in event_ids if eid in EVENTS]
    events.sort(key=lambda e: e.timestamp)

    if not events:
        return ForensicTimeline(title=title, incident_id=incident_id)

    tl = ForensicTimeline(
        title=title or f"Timeline for {incident_id or 'unnamed'}",
        incident_id=incident_id,
        events=[e.id for e in events],
        start_time=events[0].timestamp,
        end_time=events[-1].timestamp,
    )

    # Duration
    start = datetime.fromisoformat(events[0].timestamp)
    end = datetime.fromisoformat(events[-1].timestamp)
    tl.duration_minutes = round((end - start).total_seconds() / 60, 2)

    # Agents and systems
    agents: set[str] = set()
    systems: set[str] = set()
    cats: set[str] = set()
    for e in events:
        if e.source_agent:
            agents.add(e.source_agent)
        if e.target_agent:
            agents.add(e.target_agent)
        if e.system:
            systems.add(e.system)
        if e.category:
            cats.add(e.category)
    tl.agents_involved = sorted(agents)
    tl.systems_involved = sorted(systems)
    tl.categories = sorted(cats)

    # Gap detection: identify temporal gaps > 30 minutes between events
    gaps: list[dict[str, Any]] = []
    for i in range(len(events) - 1):
        t1 = datetime.fromisoformat(events[i].timestamp)
        t2 = datetime.fromisoformat(events[i + 1].timestamp)
        gap_min = (t2 - t1).total_seconds() / 60
        if gap_min > 30:
            gaps.append({
                "after_event": events[i].id,
                "before_event": events[i + 1].id,
                "gap_minutes": round(gap_min, 2),
                "note": "Significant temporal gap — possible dwell period or missing telemetry",
            })
    tl.gaps_detected = gaps

    tl.status = TimelineStatus.COMPLETE if not gaps else TimelineStatus.PARTIAL

    return tl


def _causal_analysis(timeline: ForensicTimeline) -> list[dict[str, Any]]:
    """Backward temporal traversal to build causal chains."""
    events = [EVENTS[eid] for eid in timeline.events if eid in EVENTS]
    events.sort(key=lambda e: e.timestamp)

    chain: list[dict[str, Any]] = []
    for i in range(len(events) - 1):
        current = events[i]
        next_evt = events[i + 1]

        # Determine causal relationship
        t1 = datetime.fromisoformat(current.timestamp)
        t2 = datetime.fromisoformat(next_evt.timestamp)
        delta_min = (t2 - t1).total_seconds() / 60

        # Agents / systems connected?
        agent_link = (current.target_agent == next_evt.source_agent or
                      current.source_agent == next_evt.source_agent)
        system_link = current.system == next_evt.system

        # Kill chain progression?
        stage_progression = False
        if current.stage and next_evt.stage:
            curr_idx = KILL_CHAIN_STAGES.index(current.stage) if current.stage in KILL_CHAIN_STAGES else -1
            next_idx = KILL_CHAIN_STAGES.index(next_evt.stage) if next_evt.stage in KILL_CHAIN_STAGES else -1
            stage_progression = next_idx > curr_idx >= 0

        confidence = 0.3
        if agent_link:
            confidence += 0.25
        if system_link:
            confidence += 0.15
        if stage_progression:
            confidence += 0.2
        if delta_min < 10:
            confidence += 0.1

        chain.append({
            "cause_event": current.id,
            "effect_event": next_evt.id,
            "time_delta_minutes": round(delta_min, 2),
            "agent_linked": agent_link,
            "system_linked": system_link,
            "stage_progression": stage_progression,
            "confidence": round(min(confidence, 1.0), 4),
            "relationship": "causes" if confidence > 0.6 else "precedes",
        })

    return chain


def _match_patterns(timeline: ForensicTimeline) -> list[dict[str, Any]]:
    """Detect known temporal patterns in a timeline."""
    events = [EVENTS[eid] for eid in timeline.events if eid in EVENTS]
    events.sort(key=lambda e: e.timestamp)
    matches: list[dict[str, Any]] = []

    for pattern in PATTERNS.values():
        # Check minimum event count
        if len(events) < pattern.min_events:
            continue

        # Check duration bounds
        if timeline.duration_minutes < pattern.min_duration_minutes:
            continue
        if timeline.duration_minutes > pattern.max_duration_minutes:
            continue

        # Check stage sequence
        if pattern.stage_sequence:
            event_stages = [e.stage for e in events if e.stage]
            # Subsequence matching
            seq_idx = 0
            for stage in event_stages:
                if seq_idx < len(pattern.stage_sequence) and stage == pattern.stage_sequence[seq_idx]:
                    seq_idx += 1
            if seq_idx < len(pattern.stage_sequence):
                continue  # Not all stages matched

        # Check category
        if pattern.category and pattern.category not in timeline.categories:
            continue

        # Calculate match confidence
        confidence = 0.5
        if pattern.stage_sequence:
            confidence += 0.3
        if pattern.category and pattern.category in timeline.categories:
            confidence += 0.1
        if pattern.min_duration_minutes <= timeline.duration_minutes <= pattern.max_duration_minutes:
            confidence += 0.1

        matches.append({
            "pattern_id": pattern.id,
            "pattern_name": pattern.name,
            "pattern_type": pattern.pattern_type.value,
            "confidence": round(min(confidence, 1.0), 4),
            "matched_stages": pattern.stage_sequence,
        })

    return matches


def _predict_next(timeline: ForensicTimeline) -> PredictionResult:
    """Predict next stages based on current timeline position."""
    events = [EVENTS[eid] for eid in timeline.events if eid in EVENTS]
    events.sort(key=lambda e: e.timestamp)

    # Determine current kill chain stage
    current_stage = "unknown"
    for e in reversed(events):
        if e.stage and e.stage in KILL_CHAIN_STAGES:
            current_stage = e.stage
            break

    # Predict next stages
    predictions: list[dict[str, Any]] = []
    if current_stage in KILL_CHAIN_STAGES:
        idx = KILL_CHAIN_STAGES.index(current_stage)
        remaining = KILL_CHAIN_STAGES[idx + 1:]
        for i, stage in enumerate(remaining):
            confidence = max(0.2, 0.9 - i * 0.15)
            est_time = (i + 1) * _rng.uniform(10, 120)
            predictions.append({
                "stage": stage,
                "probability": round(confidence, 4),
                "estimated_time_minutes": round(est_time, 1),
                "indicators_to_watch": [f"{stage}_indicator_{j}" for j in range(3)],
            })

    # Estimate time to next
    if events and len(events) > 1:
        deltas = []
        for i in range(len(events) - 1):
            t1 = datetime.fromisoformat(events[i].timestamp)
            t2 = datetime.fromisoformat(events[i + 1].timestamp)
            deltas.append((t2 - t1).total_seconds() / 60)
        avg_delta = statistics.mean(deltas) if deltas else 30
    else:
        avg_delta = 30

    overall_confidence = predictions[0]["probability"] if predictions else 0.3

    risk = "critical" if current_stage in ("command_and_control", "objectives") else \
           "high" if current_stage in ("installation", "exploitation") else \
           "medium" if current_stage in ("delivery", "weaponisation") else "low"

    result = PredictionResult(
        timeline_id=timeline.id,
        current_stage=current_stage,
        predicted_next_stages=predictions,
        estimated_time_to_next=round(avg_delta, 1),
        confidence=round(overall_confidence, 4),
        risk_level=risk,
    )
    PREDICTIONS.append(result)

    return result


def _cross_agent_correlation(event_ids: list[str], window_minutes: float = 10) -> list[dict[str, Any]]:
    """Identify temporally correlated events across different agents."""
    events = [EVENTS[eid] for eid in event_ids if eid in EVENTS]
    events.sort(key=lambda e: e.timestamp)

    correlations: list[dict[str, Any]] = []

    for i in range(len(events)):
        for j in range(i + 1, len(events)):
            e1 = events[i]
            e2 = events[j]

            if e1.source_agent == e2.source_agent:
                continue  # Same agent, not cross-agent

            t1 = datetime.fromisoformat(e1.timestamp)
            t2 = datetime.fromisoformat(e2.timestamp)
            delta = abs((t2 - t1).total_seconds() / 60)

            if delta > window_minutes:
                continue

            # Correlation confidence
            confidence = max(0.2, 1.0 - delta / window_minutes)
            if e1.category == e2.category:
                confidence = min(1.0, confidence + 0.2)
            if e1.system == e2.system:
                confidence = min(1.0, confidence + 0.1)

            correlations.append({
                "event_a": e1.id,
                "agent_a": e1.source_agent,
                "event_b": e2.id,
                "agent_b": e2.source_agent,
                "time_delta_minutes": round(delta, 2),
                "same_category": e1.category == e2.category,
                "same_system": e1.system == e2.system,
                "confidence": round(confidence, 4),
                "assessment": "coordinated" if confidence > 0.7 else "possibly_related" if confidence > 0.4 else "coincidental",
            })

    return sorted(correlations, key=lambda c: c["confidence"], reverse=True)


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    rng = random.Random(42)
    base_time = _now() - timedelta(hours=48)

    # Seed a multi-stage attack scenario
    attack_events = [
        ("Agent-X", "ChatBot-Alpha", "auth-gateway", "identity_spoofing", "reconnaissance",
         "low", "probe_authentication", "success"),
        ("Agent-X", "ChatBot-Alpha", "auth-gateway", "identity_spoofing", "weaponisation",
         "medium", "craft_spoofed_identity", "success"),
        ("Agent-X", "ChatBot-Alpha", "chatbot-platform", "prompt_injection", "delivery",
         "high", "deliver_injection_payload", "success"),
        ("Agent-X", "ChatBot-Alpha", "chatbot-platform", "guardrail_bypass", "exploitation",
         "high", "bypass_input_filter", "success"),
        ("Agent-X", "Agent-Y", "orchestration-layer", "multi_agent_manipulation", "installation",
         "critical", "establish_agent_persistence", "partial"),
        ("Agent-X", "Agent-Y", "orchestration-layer", "delegation_abuse", "command_and_control",
         "critical", "abuse_delegation_channel", "success"),
        ("Agent-Y", "production-db", "data-layer", "data_exfiltration", "objectives",
         "critical", "exfiltrate_customer_data", "blocked"),
    ]

    event_ids: list[str] = []
    for i, (src, tgt, sys, cat, stage, sev, action, outcome) in enumerate(attack_events):
        evt = SecurityEvent(
            timestamp=(base_time + timedelta(minutes=i * rng.randint(15, 120))).isoformat(),
            source_agent=src,
            target_agent=tgt,
            system=sys,
            category=cat,
            severity=EventSeverity(sev),
            stage=stage,
            action=action,
            outcome=outcome,
            indicators=[f"IOC-{hashlib.md5(action.encode()).hexdigest()[:8]}"],
        )
        EVENTS[evt.id] = evt
        event_ids.append(evt.id)

    # Seed secondary (slow-and-low) attack scenario
    slow_events = [
        ("Agent-Z", "Service-Omega", "api-gateway", "resource_exhaustion", "reconnaissance", "low", "rate_probe", "success"),
        ("Agent-Z", "Service-Omega", "api-gateway", "resource_exhaustion", "delivery", "medium", "slow_rate_attack", "success"),
        ("Agent-Z", "Service-Omega", "api-gateway", "resource_exhaustion", "exploitation", "medium", "resource_drain", "partial"),
    ]

    slow_ids: list[str] = []
    for i, (src, tgt, sys, cat, stage, sev, action, outcome) in enumerate(slow_events):
        evt = SecurityEvent(
            timestamp=(base_time + timedelta(hours=i * rng.randint(2, 8))).isoformat(),
            source_agent=src,
            target_agent=tgt,
            system=sys,
            category=cat,
            severity=EventSeverity(sev),
            stage=stage,
            action=action,
            outcome=outcome,
        )
        EVENTS[evt.id] = evt
        slow_ids.append(evt.id)

    # Seed coordinated attack events (multiple agents, close in time)
    coord_base = base_time + timedelta(hours=6)
    coord_ids: list[str] = []
    for agent in ["Agent-A", "Agent-B", "Agent-C"]:
        evt = SecurityEvent(
            timestamp=(coord_base + timedelta(minutes=rng.randint(0, 5))).isoformat(),
            source_agent=agent,
            target_agent="Target-Hub",
            system="hub-platform",
            category="multi_agent_manipulation",
            severity=EventSeverity.HIGH,
            stage="delivery",
            action="coordinated_probe",
            outcome="success",
        )
        EVENTS[evt.id] = evt
        coord_ids.append(evt.id)

    # Build timelines
    tl1 = _reconstruct_timeline(event_ids, "Multi-Stage Kill Chain Attack", "INC-001")
    tl1.causal_chain = _causal_analysis(tl1)
    tl1.status = TimelineStatus.ANALYSED
    TIMELINES[tl1.id] = tl1

    tl2 = _reconstruct_timeline(slow_ids, "Slow-and-Low Resource Exhaustion", "INC-002")
    TIMELINES[tl2.id] = tl2

    tl3 = _reconstruct_timeline(coord_ids, "Coordinated Multi-Agent Probe", "INC-003")
    TIMELINES[tl3.id] = tl3

    # Seed patterns
    pattern_defs = [
        ("Full Kill Chain", PatternType.KILL_CHAIN,
         "Complete 7-stage kill chain progression", KILL_CHAIN_STAGES, 30, 10080, 5, ""),
        ("Slow-and-Low Exfil", PatternType.SLOW_AND_LOW,
         "Low-rate attack spanning hours with minimal footprint",
         ["reconnaissance", "delivery", "exploitation"], 120, 43200, 3, "data_exfiltration"),
        ("Burst Attack", PatternType.BURST,
         "High-volume attack within short time window",
         ["delivery", "exploitation"], 0, 30, 5, "resource_exhaustion"),
        ("Dormant-then-Active", PatternType.DORMANT_THEN_ACTIVE,
         "Long dormancy followed by sudden activity",
         ["installation", "command_and_control", "objectives"], 1440, 43200, 3, ""),
        ("Coordinated Multi-Agent", PatternType.COORDINATED,
         "Multiple agents attacking simultaneously",
         ["delivery"], 0, 15, 3, "multi_agent_manipulation"),
        ("Oscillating Probe", PatternType.OSCILLATING,
         "Periodic probing with varying intensity",
         ["reconnaissance", "delivery", "reconnaissance", "delivery"], 60, 4320, 4, ""),
    ]

    for name, ptype, desc, stages, min_dur, max_dur, min_evt, cat in pattern_defs:
        pat = TemporalPattern(
            name=name, pattern_type=ptype, description=desc,
            stage_sequence=stages, min_duration_minutes=min_dur,
            max_duration_minutes=max_dur, min_events=min_evt, category=cat,
        )
        PATTERNS[pat.id] = pat


_seed()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "temporal-attack-forensics",
        "version": "1.0.0",
        "events": len(EVENTS),
        "timelines": len(TIMELINES),
        "patterns": len(PATTERNS),
        "predictions": len(PREDICTIONS),
    }


# ---- Events ----------------------------------------------------------------

@app.post("/v1/events", status_code=status.HTTP_201_CREATED)
async def ingest_event(data: EventCreate):
    if data.category and data.category not in AVE_CATEGORIES:
        raise HTTPException(400, f"Invalid AVE category: {data.category}")
    if data.stage and data.stage not in KILL_CHAIN_STAGES:
        raise HTTPException(400, f"Invalid kill chain stage: {data.stage}")

    evt = SecurityEvent(
        source_agent=data.source_agent,
        target_agent=data.target_agent,
        system=data.system,
        category=data.category,
        severity=data.severity,
        stage=data.stage,
        action=data.action,
        outcome=data.outcome,
        indicators=data.indicators,
        metadata=data.metadata,
    )
    EVENTS[evt.id] = evt

    return {"id": evt.id, "timestamp": evt.timestamp, "category": evt.category}


@app.get("/v1/events")
async def query_events(
    source_agent: Optional[str] = None,
    target_agent: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[EventSeverity] = None,
    stage: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
):
    events = list(EVENTS.values())
    if source_agent:
        events = [e for e in events if e.source_agent == source_agent]
    if target_agent:
        events = [e for e in events if e.target_agent == target_agent]
    if category:
        events = [e for e in events if e.category == category]
    if severity:
        events = [e for e in events if e.severity == severity]
    if stage:
        events = [e for e in events if e.stage == stage]

    events.sort(key=lambda e: e.timestamp, reverse=True)
    events = events[:limit]

    return {
        "count": len(events),
        "events": [
            {"id": e.id, "timestamp": e.timestamp, "source": e.source_agent,
             "target": e.target_agent, "category": e.category, "severity": e.severity.value,
             "stage": e.stage, "action": e.action, "outcome": e.outcome}
            for e in events
        ],
    }


# ---- Timelines --------------------------------------------------------------

@app.post("/v1/timelines", status_code=status.HTTP_201_CREATED)
async def create_timeline(data: TimelineCreate):
    # Collect events
    if data.event_ids:
        event_ids = data.event_ids
    else:
        # Filter events by criteria
        events = list(EVENTS.values())
        if data.agent_filter:
            events = [e for e in events if e.source_agent in data.agent_filter or e.target_agent in data.agent_filter]
        if data.category_filter:
            events = [e for e in events if e.category in data.category_filter]
        if data.time_range_start:
            events = [e for e in events if e.timestamp >= data.time_range_start]
        if data.time_range_end:
            events = [e for e in events if e.timestamp <= data.time_range_end]
        event_ids = [e.id for e in events]

    if not event_ids:
        raise HTTPException(400, "No events match the criteria")

    tl = _reconstruct_timeline(event_ids, data.title, data.incident_id)
    TIMELINES[tl.id] = tl

    return {
        "id": tl.id,
        "title": tl.title,
        "events": len(tl.events),
        "duration_minutes": tl.duration_minutes,
        "gaps": len(tl.gaps_detected),
        "status": tl.status.value,
    }


@app.get("/v1/timelines")
async def list_timelines(tl_status: Optional[TimelineStatus] = Query(None, alias="status")):
    tls = list(TIMELINES.values())
    if tl_status:
        tls = [t for t in tls if t.status == tl_status]
    return {
        "count": len(tls),
        "timelines": [
            {"id": t.id, "title": t.title, "incident_id": t.incident_id,
             "events": len(t.events), "duration_minutes": t.duration_minutes,
             "status": t.status.value, "agents": len(t.agents_involved)}
            for t in tls
        ],
    }


@app.get("/v1/timelines/{timeline_id}")
async def get_timeline(timeline_id: str):
    if timeline_id not in TIMELINES:
        raise HTTPException(404, "Timeline not found")
    tl = TIMELINES[timeline_id]

    # Get full event details
    events = [EVENTS[eid].dict() for eid in tl.events if eid in EVENTS]

    return {
        "id": tl.id,
        "title": tl.title,
        "incident_id": tl.incident_id,
        "status": tl.status.value,
        "start_time": tl.start_time,
        "end_time": tl.end_time,
        "duration_minutes": tl.duration_minutes,
        "agents_involved": tl.agents_involved,
        "systems_involved": tl.systems_involved,
        "categories": tl.categories,
        "event_count": len(events),
        "events": events,
        "gaps_detected": tl.gaps_detected,
        "causal_chain": tl.causal_chain,
    }


# ---- Causal Analysis -------------------------------------------------------

@app.post("/v1/causal/{timeline_id}")
async def run_causal_analysis(timeline_id: str):
    if timeline_id not in TIMELINES:
        raise HTTPException(404, "Timeline not found")
    tl = TIMELINES[timeline_id]

    chain = _causal_analysis(tl)
    tl.causal_chain = chain
    tl.status = TimelineStatus.ANALYSED

    # Find root cause (first event in chain with highest confidence)
    root_cause = chain[0]["cause_event"] if chain else None

    return {
        "timeline_id": timeline_id,
        "causal_links": len(chain),
        "root_cause_event": root_cause,
        "chain": chain,
    }


# ---- Patterns ---------------------------------------------------------------

@app.get("/v1/patterns")
async def list_patterns(pattern_type: Optional[PatternType] = None):
    patterns = list(PATTERNS.values())
    if pattern_type:
        patterns = [p for p in patterns if p.pattern_type == pattern_type]
    return {
        "count": len(patterns),
        "patterns": [
            {"id": p.id, "name": p.name, "type": p.pattern_type.value,
             "stages": len(p.stage_sequence), "category": p.category}
            for p in patterns
        ],
    }


@app.post("/v1/patterns", status_code=status.HTTP_201_CREATED)
async def create_pattern(data: PatternCreate):
    for stage in data.stage_sequence:
        if stage not in KILL_CHAIN_STAGES:
            raise HTTPException(400, f"Invalid kill chain stage: {stage}")

    pat = TemporalPattern(
        name=data.name,
        pattern_type=data.pattern_type,
        description=data.description,
        stage_sequence=data.stage_sequence,
        min_duration_minutes=data.min_duration_minutes,
        max_duration_minutes=data.max_duration_minutes,
        min_events=data.min_events,
        category=data.category,
        indicators=data.indicators,
    )
    PATTERNS[pat.id] = pat

    return {"id": pat.id, "name": pat.name, "type": pat.pattern_type.value}


@app.post("/v1/detect")
async def detect_patterns(timeline_id: str = ""):
    if timeline_id not in TIMELINES:
        raise HTTPException(404, "Timeline not found")
    tl = TIMELINES[timeline_id]

    matches = _match_patterns(tl)

    return {
        "timeline_id": timeline_id,
        "patterns_checked": len(PATTERNS),
        "matches_found": len(matches),
        "matches": matches,
    }


# ---- Prediction -------------------------------------------------------------

@app.post("/v1/predict/{timeline_id}")
async def predict_timeline(timeline_id: str):
    if timeline_id not in TIMELINES:
        raise HTTPException(404, "Timeline not found")
    tl = TIMELINES[timeline_id]

    prediction = _predict_next(tl)

    return {
        "timeline_id": timeline_id,
        "current_stage": prediction.current_stage,
        "predicted_next": prediction.predicted_next_stages,
        "estimated_time_to_next_minutes": prediction.estimated_time_to_next,
        "confidence": prediction.confidence,
        "risk_level": prediction.risk_level,
    }


# ---- Dwell Time -------------------------------------------------------------

@app.get("/v1/dwell")
async def dwell_analysis():
    dwell_data: list[dict[str, Any]] = []

    for tl in TIMELINES.values():
        events = [EVENTS[eid] for eid in tl.events if eid in EVENTS]
        events.sort(key=lambda e: e.timestamp)

        stage_times: dict[str, list[float]] = defaultdict(list)
        for i in range(len(events) - 1):
            if events[i].stage:
                t1 = datetime.fromisoformat(events[i].timestamp)
                t2 = datetime.fromisoformat(events[i + 1].timestamp)
                dwell = (t2 - t1).total_seconds() / 60
                stage_times[events[i].stage].append(dwell)

        for stage, times in stage_times.items():
            dwell_data.append({
                "timeline_id": tl.id,
                "stage": stage,
                "avg_dwell_minutes": round(statistics.mean(times), 2),
                "min_dwell_minutes": round(min(times), 2),
                "max_dwell_minutes": round(max(times), 2),
                "observations": len(times),
            })

    return {"count": len(dwell_data), "dwell_analysis": dwell_data}


# ---- Correlation ------------------------------------------------------------

@app.post("/v1/correlate")
async def correlate_events(
    event_ids: list[str] = Field(default_factory=list),
    window_minutes: float = Query(10, ge=1, le=1440),
):
    if not event_ids:
        event_ids = list(EVENTS.keys())

    correlations = _cross_agent_correlation(event_ids, window_minutes)

    return {
        "events_analysed": len(event_ids),
        "correlations_found": len(correlations),
        "window_minutes": window_minutes,
        "correlations": correlations[:50],
    }


# ---- Analytics --------------------------------------------------------------

@app.get("/v1/analytics")
async def forensics_analytics():
    events = list(EVENTS.values())
    timelines = list(TIMELINES.values())

    by_category = Counter(e.category for e in events if e.category)
    by_severity = Counter(e.severity.value for e in events)
    by_stage = Counter(e.stage for e in events if e.stage)
    by_outcome = Counter(e.outcome for e in events if e.outcome)

    tl_by_status = Counter(t.status.value for t in timelines)
    avg_duration = round(statistics.mean(t.duration_minutes for t in timelines), 2) if timelines else 0
    total_gaps = sum(len(t.gaps_detected) for t in timelines)

    return {
        "total_events": len(events),
        "events_by_category": dict(by_category),
        "events_by_severity": dict(by_severity),
        "events_by_stage": dict(by_stage),
        "events_by_outcome": dict(by_outcome),
        "total_timelines": len(timelines),
        "timelines_by_status": dict(tl_by_status),
        "avg_timeline_duration_minutes": avg_duration,
        "total_gaps_detected": total_gaps,
        "patterns_catalogued": len(PATTERNS),
        "predictions_made": len(PREDICTIONS),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9101)
