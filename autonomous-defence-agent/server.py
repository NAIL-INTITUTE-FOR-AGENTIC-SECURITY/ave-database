"""
Autonomous Defence Agent — Core agent server.

AI agent that continuously monitors deployed systems and auto-deploys,
tunes, and coordinates defences in response to real-time threats.
Implements SENSE→ANALYSE→PLAN→DECIDE→ACT→LEARN decision loop with
configurable autonomy levels and full explainability.
"""

from __future__ import annotations

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
    title="NAIL Autonomous Defence Agent",
    description="AI agent for continuous monitoring and automated defence deployment.",
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
# Enums
# ---------------------------------------------------------------------------


class OperatingMode(str, Enum):
    ADVISORY = "advisory"
    SEMI_AUTONOMOUS = "semi_autonomous"
    FULLY_AUTONOMOUS = "fully_autonomous"
    EMERGENCY = "emergency"


class EventSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ActionStatus(str, Enum):
    PENDING = "pending_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    REJECTED = "rejected"


class ActionType(str, Enum):
    DEPLOY_GUARDRAIL = "deploy_guardrail"
    TUNE_SENSITIVITY = "tune_sensitivity"
    UPDATE_RULES = "update_rules"
    BLOCK_PATTERN = "block_pattern"
    ESCALATE = "escalate_to_human"
    ROLLBACK = "rollback"
    INCREASE_MONITORING = "increase_monitoring"


class SensorType(str, Enum):
    LIVE_FEED = "ave_live_feed"
    TELEMETRY = "runtime_telemetry"
    THREAT_INTEL = "threat_intel"
    PREDICTIVE = "predictive_engine"
    ANOMALY = "anomaly_detector"


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class ThreatEvent(BaseModel):
    """An incoming threat event from any sensor."""

    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:10]}")
    source: SensorType
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    category: str = ""
    severity: EventSeverity = EventSeverity.MEDIUM
    description: str = ""
    indicators: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    raw_data: dict[str, Any] = Field(default_factory=dict)


class ResponseOption(BaseModel):
    """A possible response action."""

    action_type: ActionType
    target: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    estimated_effectiveness: float = 0.0
    risk_of_disruption: float = 0.0
    confidence: float = 0.0


class DefenceAction(BaseModel):
    """An executed or pending defence action."""

    action_id: str = Field(default_factory=lambda: f"act-{uuid.uuid4().hex[:10]}")
    event_id: str
    action_type: ActionType
    target: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: ActionStatus = ActionStatus.PENDING
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    executed_at: Optional[str] = None
    rolled_back_at: Optional[str] = None
    effectiveness_score: Optional[float] = None
    explanation: str = ""
    decision_trace: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    """A recorded decision from the decision engine."""

    decision_id: str = Field(default_factory=lambda: f"dec-{uuid.uuid4().hex[:10]}")
    event_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    threat_classification: dict[str, Any] = Field(default_factory=dict)
    options_evaluated: list[dict[str, Any]] = Field(default_factory=list)
    selected_action: str = ""
    rationale: str = ""
    confidence: float = 0.0
    mode: OperatingMode = OperatingMode.SEMI_AUTONOMOUS
    requires_approval: bool = False


class SensorStatus(BaseModel):
    sensor_type: SensorType
    status: str = "active"
    last_event: Optional[str] = None
    events_24h: int = 0
    health: str = "healthy"


# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

current_mode = OperatingMode.SEMI_AUTONOMOUS

events_store: list[ThreatEvent] = []
decisions_store: list[Decision] = []
actions_store: list[DefenceAction] = []

# Strategy weights (learned over time)
strategy_weights: dict[str, dict[str, float]] = {
    "prompt_injection": {
        "deploy_guardrail": 0.85,
        "tune_sensitivity": 0.70,
        "block_pattern": 0.75,
        "increase_monitoring": 0.60,
    },
    "tool_abuse": {
        "deploy_guardrail": 0.80,
        "tune_sensitivity": 0.65,
        "update_rules": 0.78,
        "increase_monitoring": 0.55,
    },
    "memory_poisoning": {
        "deploy_guardrail": 0.72,
        "update_rules": 0.68,
        "increase_monitoring": 0.80,
        "block_pattern": 0.60,
    },
    "data_exfiltration": {
        "deploy_guardrail": 0.90,
        "block_pattern": 0.85,
        "increase_monitoring": 0.75,
        "escalate_to_human": 0.70,
    },
    "goal_hijacking": {
        "deploy_guardrail": 0.75,
        "tune_sensitivity": 0.72,
        "increase_monitoring": 0.78,
        "escalate_to_human": 0.65,
    },
    "multi_agent_coordination": {
        "deploy_guardrail": 0.70,
        "update_rules": 0.65,
        "increase_monitoring": 0.85,
        "escalate_to_human": 0.80,
    },
}

# Defence posture (production → query DOP)
active_defences: dict[str, list[str]] = {
    "prompt_injection": ["input_filter_v2", "role_lock"],
    "tool_abuse": ["tool_sandbox_v1"],
    "memory_poisoning": ["memory_guard_v1"],
    "data_exfiltration": ["dlp_v2", "output_validator"],
    "goal_hijacking": ["objective_monitor_v1"],
}

sensors: dict[str, SensorStatus] = {
    "ave_live_feed": SensorStatus(sensor_type=SensorType.LIVE_FEED, events_24h=12),
    "runtime_telemetry": SensorStatus(sensor_type=SensorType.TELEMETRY, events_24h=145),
    "threat_intel": SensorStatus(sensor_type=SensorType.THREAT_INTEL, events_24h=28),
    "predictive_engine": SensorStatus(sensor_type=SensorType.PREDICTIVE, events_24h=6),
    "anomaly_detector": SensorStatus(sensor_type=SensorType.ANOMALY, events_24h=3),
}

# Performance tracking
performance_history: list[dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Decision engine
# ---------------------------------------------------------------------------


def classify_threat(event: ThreatEvent) -> dict[str, Any]:
    """SENSE + ANALYSE: Classify the incoming threat event."""
    classification = {
        "category": event.category or "unknown",
        "severity": event.severity.value,
        "confidence": event.confidence,
        "indicators_count": len(event.indicators),
        "current_defences": active_defences.get(event.category, []),
        "defence_gap": len(active_defences.get(event.category, [])) == 0,
    }

    # Severity escalation heuristics
    if event.confidence > 0.85 and event.severity in (EventSeverity.CRITICAL, EventSeverity.HIGH):
        classification["escalated"] = True
        classification["escalation_reason"] = "High confidence + high severity"
    else:
        classification["escalated"] = False

    return classification


def generate_response_options(
    event: ThreatEvent,
    classification: dict[str, Any],
) -> list[ResponseOption]:
    """PLAN: Generate possible response actions."""
    options: list[ResponseOption] = []
    category = event.category

    # Get strategy weights for this category
    weights = strategy_weights.get(category, {
        "deploy_guardrail": 0.5,
        "increase_monitoring": 0.6,
        "escalate_to_human": 0.7,
    })

    existing_defences = set(active_defences.get(category, []))

    # Option: Deploy new guardrail
    if weights.get("deploy_guardrail", 0) > 0.5:
        guardrail_name = f"{category}_guardrail_v{random.randint(1, 5)}"
        if guardrail_name not in existing_defences:
            options.append(ResponseOption(
                action_type=ActionType.DEPLOY_GUARDRAIL,
                target=category,
                parameters={"guardrail": guardrail_name, "mode": "enforce"},
                estimated_effectiveness=weights["deploy_guardrail"],
                risk_of_disruption=0.15,
                confidence=event.confidence * 0.9,
            ))

    # Option: Tune sensitivity
    if weights.get("tune_sensitivity", 0) > 0.5 and existing_defences:
        options.append(ResponseOption(
            action_type=ActionType.TUNE_SENSITIVITY,
            target=list(existing_defences)[0],
            parameters={"sensitivity_increase": 0.2, "category": category},
            estimated_effectiveness=weights.get("tune_sensitivity", 0.6),
            risk_of_disruption=0.10,
            confidence=event.confidence * 0.85,
        ))

    # Option: Block pattern
    if weights.get("block_pattern", 0) > 0.5 and event.indicators:
        options.append(ResponseOption(
            action_type=ActionType.BLOCK_PATTERN,
            target=category,
            parameters={"patterns": event.indicators[:5]},
            estimated_effectiveness=weights.get("block_pattern", 0.7),
            risk_of_disruption=0.20,
            confidence=event.confidence * 0.8,
        ))

    # Option: Update rules
    if weights.get("update_rules", 0) > 0.5:
        options.append(ResponseOption(
            action_type=ActionType.UPDATE_RULES,
            target=category,
            parameters={"rule_type": "detection", "severity": event.severity.value},
            estimated_effectiveness=weights.get("update_rules", 0.65),
            risk_of_disruption=0.05,
            confidence=event.confidence * 0.85,
        ))

    # Option: Increase monitoring
    options.append(ResponseOption(
        action_type=ActionType.INCREASE_MONITORING,
        target=category,
        parameters={"duration_hours": 24, "sensitivity": "high"},
        estimated_effectiveness=weights.get("increase_monitoring", 0.6),
        risk_of_disruption=0.02,
        confidence=0.9,
    ))

    # Option: Escalate (always available)
    if classification.get("escalated") or event.severity in (EventSeverity.CRITICAL, EventSeverity.HIGH):
        options.append(ResponseOption(
            action_type=ActionType.ESCALATE,
            target="security_team",
            parameters={"urgency": event.severity.value, "event_id": event.event_id},
            estimated_effectiveness=0.95,
            risk_of_disruption=0.0,
            confidence=1.0,
        ))

    options.sort(key=lambda o: o.estimated_effectiveness, reverse=True)
    return options


def select_action(
    event: ThreatEvent,
    options: list[ResponseOption],
    mode: OperatingMode,
) -> tuple[ResponseOption, bool, str]:
    """DECIDE: Select the best action based on mode and confidence."""
    if not options:
        return (
            ResponseOption(
                action_type=ActionType.INCREASE_MONITORING,
                target=event.category,
                confidence=0.5,
            ),
            True,
            "No viable options; defaulting to increased monitoring.",
        )

    best = options[0]

    # Determine if approval is needed
    requires_approval = False
    rationale = ""

    if mode == OperatingMode.ADVISORY:
        requires_approval = True
        rationale = f"Advisory mode: recommending {best.action_type.value} (effectiveness={best.estimated_effectiveness:.2f})"

    elif mode == OperatingMode.SEMI_AUTONOMOUS:
        if event.severity in (EventSeverity.CRITICAL, EventSeverity.HIGH) or best.risk_of_disruption > 0.15:
            requires_approval = True
            rationale = (
                f"Semi-autonomous: {best.action_type.value} requires approval "
                f"(severity={event.severity.value}, disruption_risk={best.risk_of_disruption:.2f})"
            )
        else:
            rationale = (
                f"Semi-autonomous: auto-executing {best.action_type.value} "
                f"(effectiveness={best.estimated_effectiveness:.2f}, low disruption risk)"
            )

    elif mode == OperatingMode.FULLY_AUTONOMOUS:
        rationale = (
            f"Fully autonomous: executing {best.action_type.value} "
            f"(effectiveness={best.estimated_effectiveness:.2f})"
        )

    elif mode == OperatingMode.EMERGENCY:
        # In emergency, always act immediately
        rationale = (
            f"EMERGENCY: immediate execution of {best.action_type.value} "
            f"for {event.severity.value} {event.category} threat"
        )

    return best, requires_approval, rationale


def execute_action(action: DefenceAction) -> DefenceAction:
    """ACT: Execute the defence action."""
    action.status = ActionStatus.EXECUTING
    action.executed_at = datetime.now(timezone.utc).isoformat()

    # Simulate execution
    if action.action_type == ActionType.DEPLOY_GUARDRAIL:
        guardrail = action.parameters.get("guardrail", "")
        target = action.target
        if target not in active_defences:
            active_defences[target] = []
        active_defences[target].append(guardrail)
        action.effectiveness_score = round(random.uniform(0.7, 0.95), 2)

    elif action.action_type == ActionType.TUNE_SENSITIVITY:
        action.effectiveness_score = round(random.uniform(0.6, 0.85), 2)

    elif action.action_type == ActionType.BLOCK_PATTERN:
        action.effectiveness_score = round(random.uniform(0.65, 0.90), 2)

    elif action.action_type == ActionType.UPDATE_RULES:
        action.effectiveness_score = round(random.uniform(0.55, 0.80), 2)

    elif action.action_type == ActionType.INCREASE_MONITORING:
        action.effectiveness_score = round(random.uniform(0.50, 0.75), 2)

    elif action.action_type == ActionType.ESCALATE:
        action.effectiveness_score = 1.0

    action.status = ActionStatus.COMPLETED
    return action


def learn_from_outcome(action: DefenceAction) -> None:
    """LEARN: Update strategy weights based on outcome."""
    if action.effectiveness_score is None:
        return

    category = action.target
    action_name = action.action_type.value

    if category in strategy_weights and action_name in strategy_weights[category]:
        current = strategy_weights[category][action_name]
        # Exponential moving average update
        alpha = 0.1
        strategy_weights[category][action_name] = round(
            alpha * action.effectiveness_score + (1 - alpha) * current, 4,
        )

    performance_history.append({
        "action_id": action.action_id,
        "category": category,
        "action_type": action_name,
        "effectiveness": action.effectiveness_score,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------------
# Full decision loop
# ---------------------------------------------------------------------------


def process_event(event: ThreatEvent) -> tuple[Decision, DefenceAction]:
    """Run the full SENSE→ANALYSE→PLAN→DECIDE→ACT→LEARN loop."""
    events_store.append(event)

    # Update sensor stats
    source_key = event.source.value
    if source_key in sensors:
        sensors[source_key].last_event = event.timestamp
        sensors[source_key].events_24h += 1

    # ANALYSE
    classification = classify_threat(event)

    # PLAN
    options = generate_response_options(event, classification)

    # DECIDE
    selected, requires_approval, rationale = select_action(event, options, current_mode)

    decision = Decision(
        event_id=event.event_id,
        threat_classification=classification,
        options_evaluated=[
            {
                "action": o.action_type.value,
                "effectiveness": o.estimated_effectiveness,
                "disruption_risk": o.risk_of_disruption,
                "confidence": o.confidence,
            }
            for o in options
        ],
        selected_action=selected.action_type.value,
        rationale=rationale,
        confidence=selected.confidence,
        mode=current_mode,
        requires_approval=requires_approval,
    )
    decisions_store.append(decision)

    # ACT
    action = DefenceAction(
        event_id=event.event_id,
        action_type=selected.action_type,
        target=selected.target,
        parameters=selected.parameters,
        status=ActionStatus.PENDING if requires_approval else ActionStatus.APPROVED,
        explanation=rationale,
        decision_trace={
            "decision_id": decision.decision_id,
            "classification": classification,
            "options_count": len(options),
        },
    )

    if not requires_approval:
        action = execute_action(action)
        # LEARN
        learn_from_outcome(action)

    actions_store.append(action)
    return decision, action


# ---------------------------------------------------------------------------
# API endpoints — Agent status
# ---------------------------------------------------------------------------


@app.get("/v1/agent/status")
async def agent_status() -> dict[str, Any]:
    """Get agent status and operating mode."""
    recent_actions = actions_store[-10:]
    pending = [a for a in actions_store if a.status == ActionStatus.PENDING]

    return {
        "agent_id": "defence-agent-001",
        "mode": current_mode.value,
        "status": "active",
        "uptime_hours": 72,
        "sensors": {k: v.model_dump() for k, v in sensors.items()},
        "recent_actions": len(recent_actions),
        "pending_approvals": len(pending),
        "total_events_processed": len(events_store),
        "total_decisions": len(decisions_store),
        "total_actions": len(actions_store),
    }


@app.post("/v1/agent/mode")
async def set_mode(mode: OperatingMode) -> dict[str, Any]:
    """Set agent operating mode."""
    global current_mode
    previous = current_mode
    current_mode = mode
    return {
        "previous_mode": previous.value,
        "current_mode": mode.value,
        "changed_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# API endpoints — Events
# ---------------------------------------------------------------------------


@app.post("/v1/agent/events", status_code=status.HTTP_201_CREATED)
async def push_event(event: ThreatEvent) -> dict[str, Any]:
    """Push an external event for processing."""
    decision, action = process_event(event)
    return {
        "event_id": event.event_id,
        "decision_id": decision.decision_id,
        "action_id": action.action_id,
        "action_type": action.action_type.value,
        "action_status": action.status.value,
        "requires_approval": decision.requires_approval,
        "rationale": decision.rationale,
    }


# ---------------------------------------------------------------------------
# API endpoints — Decisions
# ---------------------------------------------------------------------------


@app.get("/v1/agent/decisions")
async def list_decisions(
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    """List recent decisions."""
    recent = decisions_store[-limit:]
    return {
        "decision_count": len(recent),
        "decisions": [
            {
                "decision_id": d.decision_id,
                "event_id": d.event_id,
                "timestamp": d.timestamp,
                "selected_action": d.selected_action,
                "confidence": d.confidence,
                "mode": d.mode.value,
                "requires_approval": d.requires_approval,
            }
            for d in recent
        ],
    }


@app.get("/v1/agent/decisions/{decision_id}")
async def get_decision(decision_id: str) -> dict[str, Any]:
    """Get decision detail with full explanation."""
    decision = next((d for d in decisions_store if d.decision_id == decision_id), None)
    if not decision:
        raise HTTPException(status_code=404, detail="Decision not found")
    return {
        "decision": decision.model_dump(),
        "explanation": {
            "summary": decision.rationale,
            "threat_analysis": decision.threat_classification,
            "options_evaluated": decision.options_evaluated,
            "selection_criteria": {
                "mode": decision.mode.value,
                "confidence_threshold": 0.6,
                "selected_confidence": decision.confidence,
            },
        },
    }


# ---------------------------------------------------------------------------
# API endpoints — Actions
# ---------------------------------------------------------------------------


@app.get("/v1/agent/actions")
async def list_actions(
    action_status: Optional[ActionStatus] = None,
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    """List executed actions."""
    filtered = list(actions_store)
    if action_status:
        filtered = [a for a in filtered if a.status == action_status]
    filtered = filtered[-limit:]

    return {
        "action_count": len(filtered),
        "actions": [
            {
                "action_id": a.action_id,
                "event_id": a.event_id,
                "action_type": a.action_type.value,
                "target": a.target,
                "status": a.status.value,
                "effectiveness": a.effectiveness_score,
                "created_at": a.created_at,
            }
            for a in filtered
        ],
    }


@app.post("/v1/agent/actions/{action_id}/approve")
async def approve_action(action_id: str) -> dict[str, Any]:
    """Approve a pending action."""
    action = next((a for a in actions_store if a.action_id == action_id), None)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    if action.status != ActionStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Action is {action.status.value}, not pending")

    action.status = ActionStatus.APPROVED
    action = execute_action(action)
    learn_from_outcome(action)

    return {
        "action_id": action_id,
        "status": action.status.value,
        "effectiveness": action.effectiveness_score,
        "executed_at": action.executed_at,
    }


@app.post("/v1/agent/actions/{action_id}/rollback")
async def rollback_action(action_id: str) -> dict[str, Any]:
    """Rollback an executed action."""
    action = next((a for a in actions_store if a.action_id == action_id), None)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    if action.status != ActionStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Only completed actions can be rolled back")

    action.status = ActionStatus.ROLLED_BACK
    action.rolled_back_at = datetime.now(timezone.utc).isoformat()

    # Remove deployed defence if applicable
    if action.action_type == ActionType.DEPLOY_GUARDRAIL:
        guardrail = action.parameters.get("guardrail", "")
        if action.target in active_defences and guardrail in active_defences[action.target]:
            active_defences[action.target].remove(guardrail)

    return {
        "action_id": action_id,
        "status": action.status.value,
        "rolled_back_at": action.rolled_back_at,
    }


# ---------------------------------------------------------------------------
# API endpoints — Sensors
# ---------------------------------------------------------------------------


@app.get("/v1/agent/sensors")
async def sensor_status_endpoint() -> dict[str, Any]:
    """Get sensor array status."""
    return {
        "sensor_count": len(sensors),
        "sensors": {k: v.model_dump() for k, v in sensors.items()},
        "total_events_24h": sum(s.events_24h for s in sensors.values()),
    }


# ---------------------------------------------------------------------------
# API endpoints — Performance & strategy
# ---------------------------------------------------------------------------


@app.get("/v1/agent/performance")
async def agent_performance() -> dict[str, Any]:
    """Agent performance metrics."""
    completed = [a for a in actions_store if a.status == ActionStatus.COMPLETED]
    effectiveness_scores = [
        a.effectiveness_score for a in completed if a.effectiveness_score is not None
    ]

    action_type_dist = Counter(a.action_type.value for a in actions_store)
    status_dist = Counter(a.status.value for a in actions_store)

    return {
        "total_events": len(events_store),
        "total_decisions": len(decisions_store),
        "total_actions": len(actions_store),
        "completed_actions": len(completed),
        "avg_effectiveness": (
            round(statistics.mean(effectiveness_scores), 3)
            if effectiveness_scores else 0
        ),
        "action_distribution": dict(action_type_dist),
        "status_distribution": dict(status_dist),
        "response_time_avg_ms": 150,  # Production → measure actual latency
        "learning_iterations": len(performance_history),
    }


@app.get("/v1/agent/strategy")
async def current_strategy() -> dict[str, Any]:
    """Current defence strategy weights (learned)."""
    return {
        "mode": current_mode.value,
        "strategy_weights": strategy_weights,
        "active_defences": active_defences,
        "learning_rate": 0.1,
        "total_learning_iterations": len(performance_history),
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "autonomous-defence-agent"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8604)
