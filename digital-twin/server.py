"""
Digital Twin Simulation Engine — Phase 20 Service 4 of 5
Port: 9403

Full-fidelity digital twin with topology modelling, attack
simulation (5 types, probabilistic outcomes), defence validation,
what-if scenario comparison, and drift detection.
"""

from __future__ import annotations

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

class TwinState(str, Enum):
    provisioning = "provisioning"
    synced = "synced"
    drifted = "drifted"
    archived = "archived"


class AttackType(str, Enum):
    injection = "injection"
    lateral_movement = "lateral_movement"
    privilege_escalation = "privilege_escalation"
    data_exfiltration = "data_exfiltration"
    coordinated_multi_agent = "coordinated_multi_agent"


class SimState(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class DriftType(str, Enum):
    topology = "topology"
    configuration = "configuration"
    policy = "policy"
    behaviour = "behaviour"


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

class TwinCreate(BaseModel):
    name: str
    description: str = ""
    environment: str = "production"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TwinRecord(TwinCreate):
    twin_id: str
    state: TwinState = TwinState.provisioning
    agent_ids: List[str] = Field(default_factory=list)
    connection_ids: List[str] = Field(default_factory=list)
    snapshot_count: int = 0
    created_at: str
    updated_at: str


class TwinAgent(BaseModel):
    name: str
    role: str
    capabilities: List[str] = Field(default_factory=list)
    trust_score: float = Field(default=0.5, ge=0.0, le=1.0)
    services: List[str] = Field(default_factory=list)
    policy_bindings: List[str] = Field(default_factory=list)
    defences: List[str] = Field(default_factory=list)


class TwinAgentRecord(TwinAgent):
    agent_id: str
    twin_id: str


class ConnectionCreate(BaseModel):
    source_agent: str
    target_agent: str
    connection_type: str = "data_flow"  # data_flow | control | trust | dependency
    policies: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ConnectionRecord(ConnectionCreate):
    connection_id: str
    twin_id: str


class SimulationCreate(BaseModel):
    twin_id: str
    attack_type: AttackType
    entry_point: str  # agent_id
    attacker_capability: float = Field(default=0.7, ge=0.0, le=1.0)
    kill_chain_stages: List[str] = Field(default_factory=lambda: [
        "reconnaissance", "weaponisation", "delivery", "exploitation", "installation", "c2", "action_on_objectives"
    ])
    max_steps: int = Field(default=20, ge=1, le=100)


class SimulationRecord(BaseModel):
    sim_id: str
    twin_id: str
    attack_type: AttackType
    state: SimState
    entry_point: str
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    blast_radius: List[str] = Field(default_factory=list)
    stages_reached: List[str] = Field(default_factory=list)
    success_probability: float = 0.0
    created_at: str


class DefenceValidation(BaseModel):
    twin_id: str
    attack_types: List[AttackType] = Field(default_factory=lambda: list(AttackType))


class ScenarioCompare(BaseModel):
    twin_id: str
    baseline_changes: Dict[str, Any] = Field(default_factory=dict)
    proposed_changes: Dict[str, Any] = Field(default_factory=dict)
    attack_type: AttackType = AttackType.injection


class DriftRecord(BaseModel):
    drift_id: str
    twin_id: str
    drift_type: DriftType
    severity: str
    description: str
    detected_at: str


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

twins: Dict[str, TwinRecord] = {}
twin_agents: Dict[str, TwinAgentRecord] = {}
connections: Dict[str, ConnectionRecord] = {}
simulations: Dict[str, SimulationRecord] = {}
drift_records: Dict[str, List[DriftRecord]] = defaultdict(list)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Simulation Helpers
# ---------------------------------------------------------------------------

def _get_twin_agents(twin_id: str) -> List[TwinAgentRecord]:
    return [a for a in twin_agents.values() if a.twin_id == twin_id]


def _get_twin_connections(twin_id: str) -> List[ConnectionRecord]:
    return [c for c in connections.values() if c.twin_id == twin_id]


def _run_simulation(sim: SimulationCreate) -> SimulationRecord:
    """Probabilistic attack simulation."""
    sid = f"SIM-{uuid.uuid4().hex[:12]}"
    agents_in_twin = _get_twin_agents(sim.twin_id)
    conns = _get_twin_connections(sim.twin_id)
    agent_map = {a.agent_id: a for a in agents_in_twin}

    if sim.entry_point not in agent_map:
        raise HTTPException(404, "Entry point agent not found in twin")

    steps = []
    compromised: Set[str] = set()
    current_agent = sim.entry_point
    stages_reached = []

    for stage_idx, stage in enumerate(sim.kill_chain_stages):
        if stage_idx >= sim.max_steps:
            break
        agent = agent_map.get(current_agent)
        if not agent:
            break
        # Defence check: does this agent have defences?
        defence_strength = len(agent.defences) * 0.15
        attack_roll = random.random() * sim.attacker_capability
        defend_roll = random.random() * (agent.trust_score + defence_strength)
        success = attack_roll > defend_roll

        step = {
            "stage": stage,
            "target_agent": current_agent,
            "attack_roll": round(attack_roll, 4),
            "defend_roll": round(defend_roll, 4),
            "success": success,
            "defences_present": agent.defences,
        }
        steps.append(step)

        if success:
            compromised.add(current_agent)
            stages_reached.append(stage)
            # Move laterally
            reachable = [c.target_agent for c in conns if c.source_agent == current_agent and c.target_agent not in compromised]
            if reachable:
                current_agent = random.choice(reachable)
            else:
                break
        else:
            step["blocked_by"] = agent.defences[:1] if agent.defences else ["trust_threshold"]
            break

    success_prob = len(stages_reached) / max(len(sim.kill_chain_stages), 1)

    return SimulationRecord(
        sim_id=sid,
        twin_id=sim.twin_id,
        attack_type=sim.attack_type,
        state=SimState.completed,
        entry_point=sim.entry_point,
        steps=steps,
        blast_radius=list(compromised),
        stages_reached=stages_reached,
        success_probability=round(success_prob, 4),
        created_at=_now(),
    )


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Digital Twin Simulation Engine",
    description="Phase 20 — Digital twin, attack simulation, defence validation, scenario comparison, drift detection",
    version="20.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {
        "service": "digital-twin-simulation-engine",
        "status": "healthy",
        "phase": 20,
        "port": 9403,
        "stats": {
            "twins": len(twins),
            "agents_modelled": len(twin_agents),
            "simulations_run": len(simulations),
        },
        "timestamp": _now(),
    }


# -- Twins ------------------------------------------------------------------

@app.post("/v1/twins", status_code=201)
def create_twin(body: TwinCreate):
    tid = f"TWIN-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = TwinRecord(**body.dict(), twin_id=tid, state=TwinState.synced, created_at=now, updated_at=now)
    twins[tid] = record
    return record.dict()


@app.get("/v1/twins")
def list_twins(state: Optional[TwinState] = None):
    results = list(twins.values())
    if state:
        results = [t for t in results if t.state == state]
    return {"twins": [t.dict() for t in results], "total": len(results)}


@app.get("/v1/twins/{twin_id}")
def get_twin(twin_id: str):
    if twin_id not in twins:
        raise HTTPException(404, "Twin not found")
    t = twins[twin_id]
    agents = [a.dict() for a in twin_agents.values() if a.twin_id == twin_id]
    conns = [c.dict() for c in connections.values() if c.twin_id == twin_id]
    return {**t.dict(), "agents": agents, "connections": conns}


@app.delete("/v1/twins/{twin_id}")
def archive_twin(twin_id: str):
    if twin_id not in twins:
        raise HTTPException(404, "Twin not found")
    twins[twin_id].state = TwinState.archived
    twins[twin_id].updated_at = _now()
    return {"archived": twin_id}


# -- Twin Agents -------------------------------------------------------------

@app.post("/v1/twins/{twin_id}/agents", status_code=201)
def add_agent_to_twin(twin_id: str, body: TwinAgent):
    if twin_id not in twins:
        raise HTTPException(404, "Twin not found")
    aid = f"TA-{uuid.uuid4().hex[:12]}"
    record = TwinAgentRecord(**body.dict(), agent_id=aid, twin_id=twin_id)
    twin_agents[aid] = record
    twins[twin_id].agent_ids.append(aid)
    twins[twin_id].updated_at = _now()
    return record.dict()


# -- Connections --------------------------------------------------------------

@app.post("/v1/twins/{twin_id}/connections", status_code=201)
def add_connection(twin_id: str, body: ConnectionCreate):
    if twin_id not in twins:
        raise HTTPException(404, "Twin not found")
    cid = f"CONN-{uuid.uuid4().hex[:12]}"
    record = ConnectionRecord(**body.dict(), connection_id=cid, twin_id=twin_id)
    connections[cid] = record
    twins[twin_id].connection_ids.append(cid)
    twins[twin_id].updated_at = _now()
    return record.dict()


# -- Simulations --------------------------------------------------------------

@app.post("/v1/simulations", status_code=201)
def run_simulation(body: SimulationCreate):
    if body.twin_id not in twins:
        raise HTTPException(404, "Twin not found")
    result = _run_simulation(body)
    simulations[result.sim_id] = result
    return result.dict()


@app.get("/v1/simulations/{sim_id}")
def get_simulation(sim_id: str):
    if sim_id not in simulations:
        raise HTTPException(404, "Simulation not found")
    return simulations[sim_id].dict()


@app.get("/v1/simulations")
def list_simulations(twin_id: Optional[str] = None, limit: int = Query(default=50, ge=1, le=500)):
    results = list(simulations.values())
    if twin_id:
        results = [s for s in results if s.twin_id == twin_id]
    results.sort(key=lambda s: s.created_at, reverse=True)
    return {"simulations": [s.dict() for s in results[:limit]], "total": len(results)}


# -- Defence Validation -------------------------------------------------------

@app.post("/v1/defence-validation")
def validate_defences(body: DefenceValidation):
    if body.twin_id not in twins:
        raise HTTPException(404, "Twin not found")
    agents = _get_twin_agents(body.twin_id)
    if not agents:
        raise HTTPException(422, "Twin has no agents")

    results_per_attack: Dict[str, Dict] = {}
    for at in body.attack_types:
        # Run 5 simulations per attack type for statistical confidence
        outcomes = []
        for _ in range(5):
            entry = random.choice(agents)
            sim_req = SimulationCreate(twin_id=body.twin_id, attack_type=at, entry_point=entry.agent_id)
            result = _run_simulation(sim_req)
            outcomes.append(result)
        avg_success = sum(o.success_probability for o in outcomes) / len(outcomes)
        avg_blast = sum(len(o.blast_radius) for o in outcomes) / len(outcomes)
        results_per_attack[at.value] = {
            "avg_success_probability": round(avg_success, 4),
            "avg_blast_radius": round(avg_blast, 2),
            "simulations_run": len(outcomes),
        }

    # Coverage matrix
    all_defences = set()
    for a in agents:
        all_defences.update(a.defences)
    coverage = {
        "total_agents": len(agents),
        "agents_with_defences": sum(1 for a in agents if a.defences),
        "unique_defences": list(all_defences),
    }
    # Gaps: agents with no defences
    gaps = [a.agent_id for a in agents if not a.defences]

    return {
        "twin_id": body.twin_id,
        "attack_results": results_per_attack,
        "coverage": coverage,
        "undefended_agents": gaps,
    }


# -- Scenario Comparison ------------------------------------------------------

@app.post("/v1/scenarios/compare")
def compare_scenarios(body: ScenarioCompare):
    if body.twin_id not in twins:
        raise HTTPException(404, "Twin not found")
    agents = _get_twin_agents(body.twin_id)
    if not agents:
        raise HTTPException(422, "Twin has no agents")

    # Baseline simulation
    entry = random.choice(agents)
    baseline_sim = SimulationCreate(twin_id=body.twin_id, attack_type=body.attack_type, entry_point=entry.agent_id)
    baseline_result = _run_simulation(baseline_sim)

    # Apply proposed changes (simulate by temporarily boosting defences)
    added_defence = body.proposed_changes.get("add_defence", "")
    if added_defence:
        for a in agents:
            a.defences.append(added_defence)

    proposed_result = _run_simulation(baseline_sim)

    # Revert
    if added_defence:
        for a in agents:
            if added_defence in a.defences:
                a.defences.remove(added_defence)

    improvement = baseline_result.success_probability - proposed_result.success_probability
    return {
        "twin_id": body.twin_id,
        "attack_type": body.attack_type.value,
        "baseline": {
            "success_probability": baseline_result.success_probability,
            "blast_radius": len(baseline_result.blast_radius),
            "stages_reached": len(baseline_result.stages_reached),
        },
        "proposed": {
            "success_probability": proposed_result.success_probability,
            "blast_radius": len(proposed_result.blast_radius),
            "stages_reached": len(proposed_result.stages_reached),
            "changes_applied": body.proposed_changes,
        },
        "improvement": round(improvement, 4),
    }


# -- Drift Detection ----------------------------------------------------------

@app.get("/v1/drift/{twin_id}")
def check_drift(twin_id: str):
    if twin_id not in twins:
        raise HTTPException(404, "Twin not found")
    # Simulated drift detection
    drifts = drift_records.get(twin_id, [])
    twin = twins[twin_id]
    if drifts:
        twin.state = TwinState.drifted
    return {
        "twin_id": twin_id,
        "state": twin.state.value,
        "drifts": [d.dict() for d in drifts],
        "drift_count": len(drifts),
    }


@app.post("/v1/drift/{twin_id}/sync")
def sync_twin(twin_id: str):
    if twin_id not in twins:
        raise HTTPException(404, "Twin not found")
    drift_records[twin_id] = []
    twins[twin_id].state = TwinState.synced
    twins[twin_id].updated_at = _now()
    return {"synced": twin_id, "state": "synced"}


# -- Analytics -----------------------------------------------------------------

@app.get("/v1/analytics")
def analytics():
    state_dist: Dict[str, int] = defaultdict(int)
    for t in twins.values():
        state_dist[t.state.value] += 1
    attack_dist: Dict[str, int] = defaultdict(int)
    for s in simulations.values():
        attack_dist[s.attack_type.value] += 1
    avg_success = round(
        sum(s.success_probability for s in simulations.values()) / max(len(simulations), 1), 4
    )
    return {
        "twins": {"total": len(twins), "state_distribution": dict(state_dist)},
        "agents_modelled": len(twin_agents),
        "connections_modelled": len(connections),
        "simulations": {
            "total": len(simulations),
            "attack_distribution": dict(attack_dist),
            "avg_success_probability": avg_success,
        },
        "drifts_detected": sum(len(d) for d in drift_records.values()),
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9403)
