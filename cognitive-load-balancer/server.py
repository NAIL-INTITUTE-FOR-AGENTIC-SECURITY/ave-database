"""
Cognitive Load Balancer — Phase 19 Service 4 of 5
Port: 9303

Pool-tier management, capability-aware task scheduling, composite
scoring (capability-weighted, least-loaded, priority-preemptive,
affinity-based), 3-tier load shedding, SLA tracking, fairness
enforcement, and cost accounting.
"""

from __future__ import annotations

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

class PoolTier(str, Enum):
    critical = "critical"
    high = "high"
    standard = "standard"
    background = "background"
    overflow = "overflow"


class TaskType(str, Enum):
    threat_analysis = "threat_analysis"
    incident_triage = "incident_triage"
    policy_evaluation = "policy_evaluation"
    ethical_deliberation = "ethical_deliberation"
    pattern_recognition = "pattern_recognition"
    report_generation = "report_generation"
    strategy_synthesis = "strategy_synthesis"
    compliance_audit = "compliance_audit"


class TaskStatus(str, Enum):
    pending = "pending"
    scheduled = "scheduled"
    in_progress = "in_progress"
    completed = "completed"
    failed = "failed"
    shed = "shed"


class SchedulingStrategy(str, Enum):
    capability_weighted = "capability_weighted"
    least_loaded = "least_loaded"
    priority_preemptive = "priority_preemptive"
    affinity_based = "affinity_based"


class LoadLevel(str, Enum):
    normal = "normal"
    elevated = "elevated"  # ≥ 80%
    high = "high"          # ≥ 90%
    critical = "critical"  # ≥ 95%


AVE_CATEGORIES: list[str] = [
    "prompt_injection", "tool_misuse", "memory_poisoning",
    "goal_hijacking", "identity_spoofing", "privilege_escalation",
    "data_exfiltration", "resource_exhaustion", "multi_agent_manipulation",
    "context_overflow", "guardrail_bypass", "output_manipulation",
    "supply_chain_compromise", "model_extraction", "reward_hacking",
    "capability_elicitation", "alignment_subversion", "delegation_abuse",
]

COGNITIVE_SKILLS: list[str] = [
    "reasoning", "analysis", "synthesis", "evaluation", "creativity", "communication",
]


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class PoolCreate(BaseModel):
    name: str
    tier: PoolTier
    max_agents: int = Field(default=20, ge=1)
    description: str = ""


class PoolRecord(PoolCreate):
    pool_id: str
    agent_ids: List[str] = Field(default_factory=list)
    current_load: float = 0.0
    created_at: str


class AgentRegister(BaseModel):
    name: str
    pool_id: str
    capacity: float = Field(default=100.0, ge=0.0, description="Max cognitive units")
    capabilities: Dict[str, float] = Field(default_factory=dict, description="category/skill -> proficiency 0-1")
    trust_score: float = Field(default=0.5, ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentRecord(AgentRegister):
    agent_id: str
    current_load: float = 0.0
    tasks_assigned: int = 0
    tasks_completed: int = 0
    tasks_failed: int = 0
    fair_share_consumed: float = 0.0
    created_at: str
    updated_at: str


class TaskCreate(BaseModel):
    task_type: TaskType
    priority: int = Field(default=5, ge=1, le=10)
    category: Optional[str] = None
    estimated_cost: float = Field(default=10.0, ge=0.1, description="Cognitive cost units")
    deadline: Optional[str] = None
    idempotency_key: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    dependencies: List[str] = Field(default_factory=list)


class TaskRecord(TaskCreate):
    task_id: str
    status: TaskStatus = TaskStatus.pending
    assigned_agent: Optional[str] = None
    assigned_pool: Optional[str] = None
    actual_cost: float = 0.0
    created_at: str
    updated_at: str
    completed_at: Optional[str] = None


class ScheduleDecision(BaseModel):
    task_id: str
    strategy: SchedulingStrategy = SchedulingStrategy.capability_weighted


class SLADefinition(BaseModel):
    task_type: TaskType
    max_wait_seconds: float = 60.0
    max_execution_seconds: float = 300.0
    target_success_rate: float = Field(default=0.99, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

pools: Dict[str, PoolRecord] = {}
agents_store: Dict[str, AgentRecord] = {}
tasks: Dict[str, TaskRecord] = {}
sla_definitions: Dict[str, SLADefinition] = {}
idempotency_keys: Dict[str, str] = {}  # key -> task_id
fairness_audit_log: List[Dict[str, Any]] = []


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scheduling Helpers
# ---------------------------------------------------------------------------

FAIR_SHARE_CAP = 0.4  # No agent gets more than 40% of total load


def _system_load() -> float:
    total_capacity = sum(a.capacity for a in agents_store.values()) or 1.0
    total_load = sum(a.current_load for a in agents_store.values())
    return total_load / total_capacity


def _load_level() -> LoadLevel:
    load = _system_load()
    if load >= 0.95:
        return LoadLevel.critical
    if load >= 0.90:
        return LoadLevel.high
    if load >= 0.80:
        return LoadLevel.elevated
    return LoadLevel.normal


def _should_shed(task: TaskRecord) -> bool:
    level = _load_level()
    if level == LoadLevel.critical and task.priority <= 3:
        return True
    if level == LoadLevel.high and task.priority <= 2:
        return True
    if level == LoadLevel.elevated and task.priority <= 1:
        return True
    return False


def _score_agent_for_task(agent: AgentRecord, task: TaskRecord, strategy: SchedulingStrategy) -> float:
    """Composite scoring for scheduling."""
    headroom = max(agent.capacity - agent.current_load, 0) / max(agent.capacity, 1)
    cap_score = 0.0
    if task.category and task.category in agent.capabilities:
        cap_score = agent.capabilities[task.category]
    task_type_skill = {
        TaskType.threat_analysis: "analysis",
        TaskType.incident_triage: "reasoning",
        TaskType.policy_evaluation: "evaluation",
        TaskType.ethical_deliberation: "reasoning",
        TaskType.pattern_recognition: "analysis",
        TaskType.report_generation: "communication",
        TaskType.strategy_synthesis: "synthesis",
        TaskType.compliance_audit: "evaluation",
    }
    skill_key = task_type_skill.get(task.task_type, "analysis")
    skill_score = agent.capabilities.get(skill_key, 0.0)

    if strategy == SchedulingStrategy.capability_weighted:
        return cap_score * 0.35 + skill_score * 0.30 + headroom * 0.20 + agent.trust_score * 0.15
    if strategy == SchedulingStrategy.least_loaded:
        return headroom * 0.70 + cap_score * 0.15 + agent.trust_score * 0.15
    if strategy == SchedulingStrategy.priority_preemptive:
        priority_bonus = task.priority / 10.0
        return priority_bonus * 0.40 + headroom * 0.30 + cap_score * 0.20 + agent.trust_score * 0.10
    # affinity_based
    affinity = 1.0 if agent.agent_id == task.payload.get("preferred_agent") else 0.0
    return affinity * 0.50 + cap_score * 0.25 + headroom * 0.15 + agent.trust_score * 0.10


def _schedule_task(task: TaskRecord, strategy: SchedulingStrategy) -> Optional[str]:
    """Find and assign the best agent. Returns agent_id or None."""
    if _should_shed(task):
        task.status = TaskStatus.shed
        task.updated_at = _now()
        return None
    candidates = [
        a for a in agents_store.values()
        if (a.capacity - a.current_load) >= task.estimated_cost
    ]
    if not candidates:
        return None
    # Fairness: skip agents over fair-share cap
    total_load = sum(a.current_load for a in agents_store.values()) or 1.0
    candidates = [
        a for a in candidates
        if a.fair_share_consumed / total_load < FAIR_SHARE_CAP or total_load < 1
    ]
    if not candidates:
        # Fallback: ignore fairness under pressure
        candidates = [
            a for a in agents_store.values()
            if (a.capacity - a.current_load) >= task.estimated_cost
        ]
    scored = [(a.agent_id, _score_agent_for_task(a, task, strategy)) for a in candidates]
    scored.sort(key=lambda x: x[1], reverse=True)
    if not scored:
        return None
    best_id = scored[0][0]
    agent = agents_store[best_id]
    agent.current_load += task.estimated_cost
    agent.tasks_assigned += 1
    agent.fair_share_consumed += task.estimated_cost
    agent.updated_at = _now()
    task.assigned_agent = best_id
    task.assigned_pool = agent.pool_id
    task.status = TaskStatus.scheduled
    task.updated_at = _now()
    return best_id


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Cognitive Load Balancer",
    description="Phase 19 — Pool management, capability-aware scheduling, load shedding, SLA, and fairness",
    version="19.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {
        "service": "cognitive-load-balancer",
        "status": "healthy",
        "phase": 19,
        "port": 9303,
        "stats": {
            "pools": len(pools),
            "agents": len(agents_store),
            "pending_tasks": sum(1 for t in tasks.values() if t.status == TaskStatus.pending),
            "system_load": round(_system_load(), 4),
            "load_level": _load_level().value,
        },
        "timestamp": _now(),
    }


# ── Pools ──────────────────────────────────────────────────────────────────

@app.post("/v1/pools", status_code=201)
def create_pool(body: PoolCreate):
    pid = f"POOL-{uuid.uuid4().hex[:12]}"
    record = PoolRecord(**body.dict(), pool_id=pid, created_at=_now())
    pools[pid] = record
    return record.dict()


@app.get("/v1/pools")
def list_pools():
    for p in pools.values():
        pool_agents = [a for a in agents_store.values() if a.pool_id == p.pool_id]
        total_cap = sum(a.capacity for a in pool_agents) or 1
        total_load = sum(a.current_load for a in pool_agents)
        p.current_load = round(total_load / total_cap, 4)
    return {"pools": [p.dict() for p in pools.values()], "total": len(pools)}


@app.get("/v1/pools/{pool_id}")
def get_pool(pool_id: str):
    if pool_id not in pools:
        raise HTTPException(404, "Pool not found")
    p = pools[pool_id]
    pool_agents = [a.dict() for a in agents_store.values() if a.pool_id == pool_id]
    return {**p.dict(), "agents": pool_agents}


# ── Agents ─────────────────────────────────────────────────────────────────

@app.post("/v1/agents", status_code=201)
def register_agent(body: AgentRegister):
    if body.pool_id not in pools:
        raise HTTPException(404, "Pool not found")
    pool = pools[body.pool_id]
    if len([a for a in agents_store.values() if a.pool_id == body.pool_id]) >= pool.max_agents:
        raise HTTPException(422, "Pool at maximum agent capacity")
    aid = f"CLB-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = AgentRecord(**body.dict(), agent_id=aid, created_at=now, updated_at=now)
    agents_store[aid] = record
    pool.agent_ids.append(aid)
    return record.dict()


@app.get("/v1/agents")
def list_agents(pool_id: Optional[str] = None, limit: int = Query(default=100, ge=1, le=1000)):
    results = list(agents_store.values())
    if pool_id:
        results = [a for a in results if a.pool_id == pool_id]
    return {"agents": [a.dict() for a in results[:limit]], "total": len(results)}


@app.get("/v1/agents/{agent_id}")
def get_agent(agent_id: str):
    if agent_id not in agents_store:
        raise HTTPException(404, "Agent not found")
    return agents_store[agent_id].dict()


# ── Tasks ──────────────────────────────────────────────────────────────────

@app.post("/v1/tasks", status_code=201)
def create_task(body: TaskCreate):
    # Idempotency check
    if body.idempotency_key and body.idempotency_key in idempotency_keys:
        existing_id = idempotency_keys[body.idempotency_key]
        if existing_id in tasks:
            return tasks[existing_id].dict()
    tid = f"TASK-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = TaskRecord(**body.dict(), task_id=tid, created_at=now, updated_at=now)
    tasks[tid] = record
    if body.idempotency_key:
        idempotency_keys[body.idempotency_key] = tid
    return record.dict()


@app.get("/v1/tasks")
def list_tasks(
    status: Optional[TaskStatus] = None,
    task_type: Optional[TaskType] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(tasks.values())
    if status:
        results = [t for t in results if t.status == status]
    if task_type:
        results = [t for t in results if t.task_type == task_type]
    results.sort(key=lambda t: t.priority, reverse=True)
    return {"tasks": [t.dict() for t in results[:limit]], "total": len(results)}


@app.get("/v1/tasks/{task_id}")
def get_task(task_id: str):
    if task_id not in tasks:
        raise HTTPException(404, "Task not found")
    return tasks[task_id].dict()


@app.post("/v1/tasks/{task_id}/complete")
def complete_task(task_id: str, success: bool = True):
    if task_id not in tasks:
        raise HTTPException(404, "Task not found")
    task = tasks[task_id]
    if task.assigned_agent and task.assigned_agent in agents_store:
        agent = agents_store[task.assigned_agent]
        agent.current_load = max(0, agent.current_load - task.estimated_cost)
        if success:
            agent.tasks_completed += 1
        else:
            agent.tasks_failed += 1
        agent.updated_at = _now()
    task.status = TaskStatus.completed if success else TaskStatus.failed
    task.actual_cost = task.estimated_cost
    task.completed_at = _now()
    task.updated_at = task.completed_at
    return task.dict()


# ── Scheduling ─────────────────────────────────────────────────────────────

@app.post("/v1/schedule/decide")
def schedule_decide(body: ScheduleDecision):
    if body.task_id not in tasks:
        raise HTTPException(404, "Task not found")
    task = tasks[body.task_id]
    if task.status not in (TaskStatus.pending,):
        raise HTTPException(422, f"Task is {task.status.value}, cannot schedule")
    agent_id = _schedule_task(task, body.strategy)
    if task.status == TaskStatus.shed:
        return {"decision": "shed", "task_id": body.task_id, "reason": "load shedding active"}
    if agent_id is None:
        return {"decision": "queued", "task_id": body.task_id, "reason": "no available agent with capacity"}
    return {
        "decision": "scheduled",
        "task_id": body.task_id,
        "assigned_agent": agent_id,
        "strategy": body.strategy.value,
    }


# ── Load ───────────────────────────────────────────────────────────────────

@app.get("/v1/load")
def load_status():
    level = _load_level()
    per_pool: Dict[str, Dict] = {}
    for p in pools.values():
        pool_agents = [a for a in agents_store.values() if a.pool_id == p.pool_id]
        cap = sum(a.capacity for a in pool_agents) or 1
        load = sum(a.current_load for a in pool_agents)
        per_pool[p.pool_id] = {
            "name": p.name,
            "tier": p.tier.value,
            "agents": len(pool_agents),
            "load_ratio": round(load / cap, 4),
        }
    return {
        "system_load": round(_system_load(), 4),
        "load_level": level.value,
        "shedding_active": level.value in ("high", "critical"),
        "pools": per_pool,
    }


# ── SLA ────────────────────────────────────────────────────────────────────

@app.post("/v1/sla", status_code=201)
def define_sla(body: SLADefinition):
    sla_definitions[body.task_type.value] = body
    return body.dict()


@app.get("/v1/sla")
def sla_overview():
    compliance: Dict[str, Dict] = {}
    for tt, sla in sla_definitions.items():
        relevant = [t for t in tasks.values() if t.task_type.value == tt and t.status in (TaskStatus.completed, TaskStatus.failed)]
        success = sum(1 for t in relevant if t.status == TaskStatus.completed)
        total = max(len(relevant), 1)
        compliance[tt] = {
            "target_success_rate": sla.target_success_rate,
            "actual_success_rate": round(success / total, 4),
            "compliant": (success / total) >= sla.target_success_rate,
            "tasks_evaluated": len(relevant),
        }
    return {"sla_compliance": compliance}


# ── Fairness ───────────────────────────────────────────────────────────────

@app.get("/v1/fairness")
def fairness_report():
    if not agents_store:
        return {"agents": [], "gini_coefficient": 0.0, "bias_detected": False}
    loads = sorted(a.fair_share_consumed for a in agents_store.values())
    n = len(loads)
    total = sum(loads) or 1.0
    # Gini coefficient
    cumulative = 0.0
    for i, l in enumerate(loads):
        cumulative += (2 * (i + 1) - n - 1) * l
    gini = cumulative / (n * total) if n > 1 else 0.0
    gini = round(abs(gini), 4)
    over_cap = [
        a.agent_id for a in agents_store.values()
        if a.fair_share_consumed / total > FAIR_SHARE_CAP
    ]
    per_agent = [
        {
            "agent_id": a.agent_id,
            "name": a.name,
            "fair_share_consumed": round(a.fair_share_consumed, 2),
            "share_pct": round(a.fair_share_consumed / total * 100, 2),
            "over_cap": a.agent_id in over_cap,
        }
        for a in agents_store.values()
    ]
    bias = gini > 0.35 or len(over_cap) > 0
    entry = {"gini": gini, "bias_detected": bias, "over_cap_agents": over_cap, "timestamp": _now()}
    fairness_audit_log.append(entry)
    if len(fairness_audit_log) > 5000:
        fairness_audit_log.pop(0)
    return {
        "agents": per_agent,
        "gini_coefficient": gini,
        "fair_share_cap": FAIR_SHARE_CAP,
        "over_cap_agents": over_cap,
        "bias_detected": bias,
    }


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/v1/analytics")
def analytics():
    status_dist: Dict[str, int] = defaultdict(int)
    type_dist: Dict[str, int] = defaultdict(int)
    for t in tasks.values():
        status_dist[t.status.value] += 1
        type_dist[t.task_type.value] += 1
    total_completed = sum(1 for t in tasks.values() if t.status == TaskStatus.completed)
    total_failed = sum(1 for t in tasks.values() if t.status == TaskStatus.failed)
    total_shed = sum(1 for t in tasks.values() if t.status == TaskStatus.shed)
    total_cost = sum(t.actual_cost for t in tasks.values() if t.status == TaskStatus.completed)
    return {
        "tasks": {
            "total": len(tasks),
            "status_distribution": dict(status_dist),
            "type_distribution": dict(type_dist),
            "completed": total_completed,
            "failed": total_failed,
            "shed": total_shed,
            "total_cost": round(total_cost, 2),
        },
        "agents": {"total": len(agents_store)},
        "pools": {"total": len(pools)},
        "system_load": round(_system_load(), 4),
        "load_level": _load_level().value,
        "fairness_audits": len(fairness_audit_log),
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9303)
