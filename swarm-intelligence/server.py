"""
Collective Intelligence Swarm — Phase 19 Service 3 of 5
Port: 9302

Agent fleet management with energy/stamina model, stigmergic
pheromone communication, dynamic task force formation, voting
protocols, and emergent strategy discovery.
"""

from __future__ import annotations

import math
import random
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AgentRole(str, Enum):
    scout = "scout"
    sentinel = "sentinel"
    hunter = "hunter"
    analyst = "analyst"
    coordinator = "coordinator"
    healer = "healer"


class AgentState(str, Enum):
    spawned = "spawned"
    idle = "idle"
    assigned = "assigned"
    active = "active"
    cooling_down = "cooling_down"
    retired = "retired"


class SignalType(str, Enum):
    threat_detected = "threat_detected"
    area_clear = "area_clear"
    help_needed = "help_needed"
    defence_active = "defence_active"
    pattern_found = "pattern_found"


class TaskForceState(str, Enum):
    forming = "forming"
    hunting = "hunting"
    analysing = "analysing"
    responding = "responding"
    disbanded = "disbanded"


class VotingProtocol(str, Enum):
    majority = "majority"
    supermajority = "supermajority"
    weighted_consensus = "weighted_consensus"


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

class SwarmAgentCreate(BaseModel):
    name: str
    role: AgentRole
    capabilities: Dict[str, float] = Field(
        default_factory=dict,
        description="Category -> proficiency (0.0-1.0)",
    )
    energy: float = Field(default=100.0, ge=0.0, le=100.0)
    stamina: float = Field(default=100.0, ge=0.0, le=100.0)
    trust_score: float = Field(default=0.5, ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SwarmAgentRecord(SwarmAgentCreate):
    agent_id: str
    state: AgentState = AgentState.spawned
    tasks_completed: int = 0
    created_at: str
    updated_at: str


class SignalCreate(BaseModel):
    signal_type: SignalType
    emitter_id: str
    intensity: float = Field(default=1.0, ge=0.0, le=10.0)
    position: Tuple[float, float] = (0.0, 0.0)
    category: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    decay_rate: float = Field(default=0.1, ge=0.0, le=1.0)


class SignalRecord(SignalCreate):
    signal_id: str
    current_intensity: float
    created_at: str


class TaskForceCreate(BaseModel):
    name: str
    objective: str
    required_roles: List[AgentRole]
    category: Optional[str] = None
    min_agents: int = Field(default=2, ge=1)
    max_agents: int = Field(default=10, ge=1)


class TaskForceRecord(TaskForceCreate):
    taskforce_id: str
    state: TaskForceState = TaskForceState.forming
    member_ids: List[str] = Field(default_factory=list)
    created_at: str
    updated_at: str


class VoteRequest(BaseModel):
    taskforce_id: str
    proposal: str
    protocol: VotingProtocol = VotingProtocol.majority
    votes: Dict[str, str] = Field(default_factory=dict)  # agent_id -> "for"|"against"|"abstain"
    quorum: float = Field(default=0.6, ge=0.0, le=1.0)


class VoteResult(BaseModel):
    proposal: str
    protocol: str
    total_eligible: int
    votes_cast: int
    quorum_met: bool
    result: str  # "passed" | "failed" | "no_quorum"
    breakdown: Dict[str, int]


class StrategyCreate(BaseModel):
    name: str
    description: str
    tactics: List[Dict[str, Any]]
    fitness_score: float = Field(default=0.5, ge=0.0, le=1.0)
    lineage: List[str] = Field(default_factory=list)


class StrategyRecord(StrategyCreate):
    strategy_id: str
    generation: int = 0
    novelty_score: float = 0.0
    created_at: str


class CrossPollinateRequest(BaseModel):
    strategy_ids: List[str]
    mutation_rate: float = Field(default=0.1, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

agents: Dict[str, SwarmAgentRecord] = {}
signals: Dict[str, SignalRecord] = {}
taskforces: Dict[str, TaskForceRecord] = {}
decisions_log: List[Dict[str, Any]] = []
strategies: Dict[str, StrategyRecord] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decay_signals():
    """Apply exponential decay to all signals; prune dead ones."""
    to_remove = []
    for sid, s in signals.items():
        s.current_intensity *= (1.0 - s.decay_rate)
        if s.current_intensity < 0.01:
            to_remove.append(sid)
    for sid in to_remove:
        del signals[sid]


def _signal_gradient(position: Tuple[float, float], signal_type: Optional[SignalType] = None) -> List[Dict[str, Any]]:
    """Compute gradient from position toward strongest signals."""
    _decay_signals()
    gradients = []
    for s in signals.values():
        if signal_type and s.signal_type != signal_type:
            continue
        dx = s.position[0] - position[0]
        dy = s.position[1] - position[1]
        dist = math.sqrt(dx * dx + dy * dy) + 0.001
        strength = s.current_intensity / dist
        gradients.append({
            "signal_id": s.signal_id,
            "signal_type": s.signal_type.value,
            "direction": (round(dx / dist, 4), round(dy / dist, 4)),
            "strength": round(strength, 4),
            "distance": round(dist, 2),
        })
    gradients.sort(key=lambda g: g["strength"], reverse=True)
    return gradients[:20]


def _match_agents_for_taskforce(tf: TaskForceRecord) -> List[str]:
    """Select best-fit idle agents for a task force."""
    candidates = [
        a for a in agents.values()
        if a.state == AgentState.idle and a.energy > 20.0
    ]
    # Score each candidate
    scored = []
    for a in candidates:
        role_match = 1.0 if a.role in tf.required_roles else 0.3
        cat_match = a.capabilities.get(tf.category, 0.0) if tf.category else 0.5
        trust = a.trust_score
        score = role_match * 0.4 + cat_match * 0.35 + trust * 0.25
        scored.append((a.agent_id, score))
    scored.sort(key=lambda x: x[1], reverse=True)
    selected = [aid for aid, _ in scored[:tf.max_agents]]
    return selected


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Collective Intelligence Swarm",
    description="Phase 19 — Agent fleet, stigmergic signals, task forces, voting, and emergent strategies",
    version="19.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    active_count = sum(1 for a in agents.values() if a.state in (AgentState.active, AgentState.assigned))
    return {
        "service": "collective-intelligence-swarm",
        "status": "healthy",
        "phase": 19,
        "port": 9302,
        "stats": {
            "total_agents": len(agents),
            "active_agents": active_count,
            "signals": len(signals),
            "taskforces": len(taskforces),
            "strategies": len(strategies),
        },
        "timestamp": _now(),
    }


# ── Agent Fleet ────────────────────────────────────────────────────────────

@app.post("/v1/agents", status_code=201)
def create_agent(body: SwarmAgentCreate):
    aid = f"SWARM-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = SwarmAgentRecord(**body.dict(), agent_id=aid, created_at=now, updated_at=now)
    record.state = AgentState.idle
    agents[aid] = record
    return record.dict()


@app.get("/v1/agents")
def list_agents(
    role: Optional[AgentRole] = None,
    state: Optional[AgentState] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(agents.values())
    if role:
        results = [a for a in results if a.role == role]
    if state:
        results = [a for a in results if a.state == state]
    return {"agents": [a.dict() for a in results[:limit]], "total": len(results)}


@app.get("/v1/agents/{agent_id}")
def get_agent(agent_id: str):
    if agent_id not in agents:
        raise HTTPException(404, "Agent not found")
    return agents[agent_id].dict()


@app.delete("/v1/agents/{agent_id}")
def retire_agent(agent_id: str):
    if agent_id not in agents:
        raise HTTPException(404, "Agent not found")
    agents[agent_id].state = AgentState.retired
    agents[agent_id].updated_at = _now()
    return {"retired": agent_id}


# ── Signals (Stigmergy) ───────────────────────────────────────────────────

@app.post("/v1/signals", status_code=201)
def emit_signal(body: SignalCreate):
    if body.emitter_id not in agents:
        raise HTTPException(404, "Emitter agent not found")
    sid = f"SIG-{uuid.uuid4().hex[:12]}"
    record = SignalRecord(
        **body.dict(),
        signal_id=sid,
        current_intensity=body.intensity,
        created_at=_now(),
    )
    signals[sid] = record
    return record.dict()


@app.get("/v1/signals")
def list_signals(signal_type: Optional[SignalType] = None):
    _decay_signals()
    results = list(signals.values())
    if signal_type:
        results = [s for s in results if s.signal_type == signal_type]
    return {"signals": [s.dict() for s in results], "total": len(results)}


@app.post("/v1/signals/gradient")
def get_gradient(
    position: Tuple[float, float] = (0.0, 0.0),
    signal_type: Optional[SignalType] = None,
):
    gradients = _signal_gradient(position, signal_type)
    return {"position": position, "gradients": gradients}


# ── Task Forces ────────────────────────────────────────────────────────────

@app.post("/v1/taskforces", status_code=201)
def create_taskforce(body: TaskForceCreate):
    tfid = f"TF-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = TaskForceRecord(**body.dict(), taskforce_id=tfid, created_at=now, updated_at=now)
    # Auto-recruit
    selected = _match_agents_for_taskforce(record)
    if len(selected) < body.min_agents:
        record.state = TaskForceState.forming
    else:
        record.state = TaskForceState.hunting
        for aid in selected:
            agents[aid].state = AgentState.assigned
            agents[aid].updated_at = now
    record.member_ids = selected
    taskforces[tfid] = record
    return record.dict()


@app.get("/v1/taskforces")
def list_taskforces(state: Optional[TaskForceState] = None):
    results = list(taskforces.values())
    if state:
        results = [t for t in results if t.state == state]
    return {"taskforces": [t.dict() for t in results], "total": len(results)}


@app.get("/v1/taskforces/{taskforce_id}")
def get_taskforce(taskforce_id: str):
    if taskforce_id not in taskforces:
        raise HTTPException(404, "Task force not found")
    tf = taskforces[taskforce_id]
    members = [agents[aid].dict() for aid in tf.member_ids if aid in agents]
    return {**tf.dict(), "members": members}


@app.post("/v1/taskforces/{taskforce_id}/disband")
def disband_taskforce(taskforce_id: str):
    if taskforce_id not in taskforces:
        raise HTTPException(404, "Task force not found")
    tf = taskforces[taskforce_id]
    tf.state = TaskForceState.disbanded
    tf.updated_at = _now()
    for aid in tf.member_ids:
        if aid in agents:
            agents[aid].state = AgentState.idle
            agents[aid].tasks_completed += 1
            agents[aid].energy = max(0, agents[aid].energy - 10)
            agents[aid].updated_at = tf.updated_at
    return {"disbanded": taskforce_id}


# ── Voting ─────────────────────────────────────────────────────────────────

@app.post("/v1/taskforces/vote")
def cast_votes(body: VoteRequest):
    if body.taskforce_id not in taskforces:
        raise HTTPException(404, "Task force not found")
    tf = taskforces[body.taskforce_id]
    eligible = set(tf.member_ids)
    total_eligible = len(eligible)

    valid_votes = {k: v for k, v in body.votes.items() if k in eligible}
    votes_cast = len(valid_votes)
    quorum_met = (votes_cast / max(total_eligible, 1)) >= body.quorum

    breakdown = {"for": 0, "against": 0, "abstain": 0}
    for v in valid_votes.values():
        if v in breakdown:
            breakdown[v] += 1

    if not quorum_met:
        result_str = "no_quorum"
    elif body.protocol == VotingProtocol.majority:
        result_str = "passed" if breakdown["for"] > breakdown["against"] else "failed"
    elif body.protocol == VotingProtocol.supermajority:
        result_str = "passed" if breakdown["for"] >= (votes_cast * 2 / 3) else "failed"
    else:  # weighted_consensus
        # Weight by trust score
        weighted_for = sum(agents[a].trust_score for a in valid_votes if valid_votes[a] == "for" and a in agents)
        weighted_against = sum(agents[a].trust_score for a in valid_votes if valid_votes[a] == "against" and a in agents)
        result_str = "passed" if weighted_for > weighted_against else "failed"

    vote_result = VoteResult(
        proposal=body.proposal,
        protocol=body.protocol.value,
        total_eligible=total_eligible,
        votes_cast=votes_cast,
        quorum_met=quorum_met,
        result=result_str,
        breakdown=breakdown,
    )
    decisions_log.append({"taskforce_id": body.taskforce_id, **vote_result.dict(), "timestamp": _now()})
    return vote_result.dict()


@app.get("/v1/taskforces/decisions")
def list_decisions(limit: int = Query(default=50, ge=1, le=500)):
    return {"decisions": decisions_log[-limit:], "total": len(decisions_log)}


# ── Strategies ─────────────────────────────────────────────────────────────

@app.post("/v1/strategies", status_code=201)
def create_strategy(body: StrategyCreate):
    sid = f"STRAT-{uuid.uuid4().hex[:12]}"
    # Novelty: compare with existing strategies
    novelty = 1.0
    for existing in strategies.values():
        overlap = len(set(str(t) for t in body.tactics) & set(str(t) for t in existing.tactics))
        total = max(len(body.tactics) + len(existing.tactics), 1)
        similarity = overlap / total
        novelty = min(novelty, 1.0 - similarity)
    record = StrategyRecord(
        **body.dict(),
        strategy_id=sid,
        novelty_score=round(novelty, 4),
        created_at=_now(),
    )
    strategies[sid] = record
    return record.dict()


@app.get("/v1/strategies")
def list_strategies(
    min_fitness: float = Query(default=0.0, ge=0.0, le=1.0),
    limit: int = Query(default=50, ge=1, le=500),
):
    results = [s for s in strategies.values() if s.fitness_score >= min_fitness]
    results.sort(key=lambda s: s.fitness_score, reverse=True)
    return {"strategies": [s.dict() for s in results[:limit]], "total": len(results)}


@app.post("/v1/strategies/cross-pollinate")
def cross_pollinate(body: CrossPollinateRequest):
    parents = [strategies[sid] for sid in body.strategy_ids if sid in strategies]
    if len(parents) < 2:
        raise HTTPException(422, "Need at least 2 existing strategies to cross-pollinate")
    # Combine tactics from parents with mutation
    combined_tactics = []
    for p in parents:
        for tactic in p.tactics:
            if random.random() > body.mutation_rate:
                combined_tactics.append(tactic)
    # Add mutated tactic
    if combined_tactics and random.random() < body.mutation_rate:
        mutant = dict(combined_tactics[0])
        mutant["mutated"] = True
        combined_tactics.append(mutant)

    avg_fitness = sum(p.fitness_score for p in parents) / len(parents)
    child = StrategyCreate(
        name=f"Evolved: {' × '.join(p.name for p in parents[:3])}",
        description="Cross-pollinated strategy combining parent tactics",
        tactics=combined_tactics,
        fitness_score=round(min(avg_fitness * 1.05, 1.0), 4),
        lineage=[p.strategy_id for p in parents],
    )
    sid = f"STRAT-{uuid.uuid4().hex[:12]}"
    record = StrategyRecord(
        **child.dict(),
        strategy_id=sid,
        generation=max(p.generation for p in parents) + 1,
        novelty_score=round(random.uniform(0.3, 0.8), 4),
        created_at=_now(),
    )
    strategies[sid] = record
    return record.dict()


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/v1/analytics")
def analytics():
    role_dist: Dict[str, int] = defaultdict(int)
    state_dist: Dict[str, int] = defaultdict(int)
    for a in agents.values():
        role_dist[a.role.value] += 1
        state_dist[a.state.value] += 1
    avg_energy = round(
        sum(a.energy for a in agents.values()) / max(len(agents), 1), 2
    )
    avg_trust = round(
        sum(a.trust_score for a in agents.values()) / max(len(agents), 1), 4
    )
    tf_state_dist: Dict[str, int] = defaultdict(int)
    for tf in taskforces.values():
        tf_state_dist[tf.state.value] += 1
    return {
        "fleet": {
            "total_agents": len(agents),
            "role_distribution": dict(role_dist),
            "state_distribution": dict(state_dist),
            "avg_energy": avg_energy,
            "avg_trust": avg_trust,
        },
        "signals": {"active_signals": len(signals)},
        "taskforces": {
            "total": len(taskforces),
            "state_distribution": dict(tf_state_dist),
        },
        "strategies": {
            "total": len(strategies),
            "avg_fitness": round(
                sum(s.fitness_score for s in strategies.values()) / max(len(strategies), 1), 4
            ),
        },
        "decisions_logged": len(decisions_log),
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9302)
