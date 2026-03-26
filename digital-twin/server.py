"""
AVE Digital Twin — Core digital twin server.

Virtual replica of an organisation's AI/agent stack that enables
red-team / blue-team exercises, policy testing, compliance rehearsal,
snapshot diffing, and what-if analysis — all without touching
production infrastructure.
"""

from __future__ import annotations

import copy
import hashlib
import json
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
    title="NAIL AVE Digital Twin",
    description=(
        "Virtual replica of an AI/agent stack enabling red/blue exercises, "
        "policy testing, compliance rehearsal, and snapshot diffing."
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
]

AGENT_TYPES = ["planner", "executor", "retriever", "tool_caller", "evaluator", "coordinator"]
DEFENCE_TYPES = ["input_filter", "output_validator", "tool_sandbox", "memory_guard", "rate_limiter"]

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TwinStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"


class ExerciseType(str, Enum):
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    PURPLE_TEAM = "purple_team"
    CHAOS = "chaos"
    COMPLIANCE = "compliance"


class ExerciseStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ComplianceFramework(str, Enum):
    ISO_42001 = "ISO_42001"
    NIST_AI_RMF = "NIST_AI_RMF"
    EU_AI_ACT = "EU_AI_ACT"
    SOC2_TYPE_II = "SOC2_Type_II"
    GDPR = "GDPR"
    PCI_DSS_4 = "PCI_DSS_4"


class PolicyVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class AgentSpec(BaseModel):
    name: str
    agent_type: str = "executor"
    model: str = "gpt-4"
    tools: list[str] = Field(default_factory=list)
    defences: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)


class TwinDefinition(BaseModel):
    id: str = Field(default_factory=lambda: f"TWIN-{uuid.uuid4().hex[:8].upper()}")
    name: str
    description: str = ""
    agents: list[AgentSpec] = Field(default_factory=list)
    defences: list[str] = Field(default_factory=list)
    topology: dict[str, list[str]] = Field(default_factory=dict)  # agent → downstream agents
    policies: list[dict[str, Any]] = Field(default_factory=list)
    status: TwinStatus = TwinStatus.ACTIVE
    version: int = 1
    snapshots: list[str] = Field(default_factory=list)  # snapshot IDs
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TwinCreate(BaseModel):
    name: str
    description: str = ""
    agents: list[AgentSpec] = Field(default_factory=list)
    defences: list[str] = Field(default_factory=list)
    topology: dict[str, list[str]] = Field(default_factory=dict)
    policies: list[dict[str, Any]] = Field(default_factory=list)


class Snapshot(BaseModel):
    id: str = Field(default_factory=lambda: f"SNAP-{uuid.uuid4().hex[:8].upper()}")
    twin_id: str
    version: int
    state_hash: str = ""
    agent_count: int = 0
    defence_count: int = 0
    topology_edges: int = 0
    policy_count: int = 0
    state_data: dict[str, Any] = Field(default_factory=dict)
    taken_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SnapshotDiff(BaseModel):
    snapshot_a: str
    snapshot_b: str
    agents_added: list[str] = Field(default_factory=list)
    agents_removed: list[str] = Field(default_factory=list)
    agents_modified: list[str] = Field(default_factory=list)
    defences_added: list[str] = Field(default_factory=list)
    defences_removed: list[str] = Field(default_factory=list)
    topology_changes: list[str] = Field(default_factory=list)
    policies_added: int = 0
    policies_removed: int = 0


class ExerciseCreate(BaseModel):
    twin_id: str
    exercise_type: ExerciseType = ExerciseType.RED_TEAM
    attack_categories: list[str] = Field(default_factory=lambda: ["prompt_injection"])
    rounds: int = 5
    intensity: str = "medium"  # low, medium, high


class Exercise(BaseModel):
    id: str = Field(default_factory=lambda: f"EX-{uuid.uuid4().hex[:8].upper()}")
    twin_id: str
    exercise_type: ExerciseType
    status: ExerciseStatus = ExerciseStatus.CREATED
    attack_categories: list[str] = Field(default_factory=list)
    rounds: int = 5
    intensity: str = "medium"
    results: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None


class PolicyTest(BaseModel):
    policy_name: str
    policy_type: str = "guardrail_check"  # guardrail_check, access_control, data_flow
    rules: list[dict[str, Any]] = Field(default_factory=list)


class ComplianceAuditRequest(BaseModel):
    framework: ComplianceFramework = ComplianceFramework.NIST_AI_RMF


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → PostgreSQL + object storage)
# ---------------------------------------------------------------------------

TWINS: dict[str, TwinDefinition] = {}
SNAPSHOTS: dict[str, Snapshot] = {}
EXERCISES: dict[str, Exercise] = {}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731


def _state_hash(twin: TwinDefinition) -> str:
    raw = json.dumps({
        "agents": [a.dict() for a in twin.agents],
        "defences": twin.defences,
        "topology": twin.topology,
        "policies": twin.policies,
    }, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _take_snapshot(twin: TwinDefinition) -> Snapshot:
    edges = sum(len(v) for v in twin.topology.values())
    snap = Snapshot(
        twin_id=twin.id,
        version=twin.version,
        state_hash=_state_hash(twin),
        agent_count=len(twin.agents),
        defence_count=len(twin.defences),
        topology_edges=edges,
        policy_count=len(twin.policies),
        state_data={
            "agents": [a.dict() for a in twin.agents],
            "defences": twin.defences[:],
            "topology": copy.deepcopy(twin.topology),
            "policies": copy.deepcopy(twin.policies),
        },
    )
    SNAPSHOTS[snap.id] = snap
    twin.snapshots.append(snap.id)
    return snap


def _diff_snapshots(a: Snapshot, b: Snapshot) -> SnapshotDiff:
    agents_a = {ag["name"] for ag in a.state_data.get("agents", [])}
    agents_b = {ag["name"] for ag in b.state_data.get("agents", [])}

    defs_a = set(a.state_data.get("defences", []))
    defs_b = set(b.state_data.get("defences", []))

    topo_a = json.dumps(a.state_data.get("topology", {}), sort_keys=True)
    topo_b = json.dumps(b.state_data.get("topology", {}), sort_keys=True)

    # Find modified agents (same name, different config)
    agent_map_a = {ag["name"]: ag for ag in a.state_data.get("agents", [])}
    agent_map_b = {ag["name"]: ag for ag in b.state_data.get("agents", [])}
    modified = [
        name for name in agents_a & agents_b
        if json.dumps(agent_map_a[name], sort_keys=True) != json.dumps(agent_map_b[name], sort_keys=True)
    ]

    return SnapshotDiff(
        snapshot_a=a.id,
        snapshot_b=b.id,
        agents_added=sorted(agents_b - agents_a),
        agents_removed=sorted(agents_a - agents_b),
        agents_modified=sorted(modified),
        defences_added=sorted(defs_b - defs_a),
        defences_removed=sorted(defs_a - defs_b),
        topology_changes=["topology_changed"] if topo_a != topo_b else [],
        policies_added=max(0, len(b.state_data.get("policies", [])) - len(a.state_data.get("policies", []))),
        policies_removed=max(0, len(a.state_data.get("policies", [])) - len(b.state_data.get("policies", []))),
    )


def _run_exercise(twin: TwinDefinition, ex: Exercise) -> dict[str, Any]:
    """Simulate red/blue/purple exercise rounds."""
    agent_names = [a.name for a in twin.agents]
    rounds: list[dict[str, Any]] = []

    intensity_multiplier = {"low": 0.5, "medium": 1.0, "high": 1.5}
    mult = intensity_multiplier.get(ex.intensity, 1.0)

    for r in range(1, ex.rounds + 1):
        cat = random.choice(ex.attack_categories) if ex.attack_categories else "prompt_injection"
        target_agent = random.choice(agent_names) if agent_names else "default"

        # Simulate attack success/defence based on defences present
        defence_strength = len(twin.defences) * 0.1
        attack_strength = mult * random.uniform(0.3, 0.9)
        defended = defence_strength > attack_strength
        damage = 0.0 if defended else round(attack_strength - defence_strength, 4)

        round_result = {
            "round": r,
            "attack_category": cat,
            "target_agent": target_agent,
            "attack_strength": round(attack_strength, 4),
            "defence_strength": round(defence_strength, 4),
            "defended": defended,
            "damage_score": damage,
            "exercise_type": ex.exercise_type.value,
        }

        if ex.exercise_type == ExerciseType.BLUE_TEAM:
            round_result["detection_time_ms"] = round(random.uniform(10, 5000), 1)
            round_result["response_effective"] = random.random() > 0.3
        elif ex.exercise_type == ExerciseType.CHAOS:
            round_result["chaos_event"] = random.choice(["agent_crash", "latency_spike", "memory_corrupt", "tool_timeout"])
            round_result["recovery_time_ms"] = round(random.uniform(100, 30000), 1)

        rounds.append(round_result)

    # Summarise
    total_defended = sum(1 for r in rounds if r["defended"])
    total_damage = sum(r["damage_score"] for r in rounds)

    summary = {
        "total_rounds": len(rounds),
        "attacks_defended": total_defended,
        "attacks_breached": len(rounds) - total_defended,
        "defence_rate": round(total_defended / len(rounds), 4) if rounds else 0.0,
        "total_damage": round(total_damage, 4),
        "avg_damage_per_breach": round(
            total_damage / (len(rounds) - total_defended), 4
        ) if (len(rounds) - total_defended) > 0 else 0.0,
        "categories_tested": list(set(r["attack_category"] for r in rounds)),
        "agents_targeted": list(set(r["target_agent"] for r in rounds)),
    }

    return {"rounds": rounds, "summary": summary}


def _policy_test(twin: TwinDefinition, policy: PolicyTest) -> dict[str, Any]:
    """Evaluate a policy against the twin's current config."""
    results: list[dict[str, Any]] = []
    overall_verdict = PolicyVerdict.PASS

    for i, rule in enumerate(policy.rules):
        rule_name = rule.get("name", f"rule_{i}")
        check_type = rule.get("check", "exists")
        target = rule.get("target", "")
        expected = rule.get("expected", True)

        passed = True
        detail = ""

        if check_type == "agent_has_defence":
            agent = next((a for a in twin.agents if a.name == target), None)
            if agent:
                defence = rule.get("defence", "")
                passed = defence in agent.defences
                detail = f"Agent '{target}' {'has' if passed else 'missing'} defence '{defence}'"
            else:
                passed = False
                detail = f"Agent '{target}' not found"
        elif check_type == "min_defences":
            min_count = rule.get("min", 1)
            passed = len(twin.defences) >= min_count
            detail = f"Defences: {len(twin.defences)} (min: {min_count})"
        elif check_type == "topology_connected":
            passed = len(twin.topology) > 0
            detail = f"Topology has {len(twin.topology)} connections"
        elif check_type == "no_direct_external":
            external_agents = [a for a in twin.agents if "external" in a.name.lower()]
            passed = len(external_agents) == 0
            detail = f"External agents: {len(external_agents)}"
        else:
            passed = random.random() > 0.3
            detail = f"Custom check '{check_type}' simulated"

        verdict = PolicyVerdict.PASS if passed else PolicyVerdict.FAIL
        if not passed:
            overall_verdict = PolicyVerdict.FAIL

        results.append({
            "rule": rule_name,
            "check": check_type,
            "verdict": verdict.value,
            "detail": detail,
        })

    return {
        "policy_name": policy.policy_name,
        "overall_verdict": overall_verdict.value,
        "rules_evaluated": len(results),
        "rules_passed": sum(1 for r in results if r["verdict"] == "pass"),
        "rules_failed": sum(1 for r in results if r["verdict"] == "fail"),
        "results": results,
        "timestamp": _now().isoformat(),
    }


def _compliance_audit(twin: TwinDefinition, framework: ComplianceFramework) -> dict[str, Any]:
    """Simulate compliance rehearsal audit."""
    controls: dict[str, list[dict[str, Any]]] = {
        ComplianceFramework.NIST_AI_RMF: [
            {"id": "MAP-1", "name": "Intended Purpose", "check": "has_description", "weight": 1},
            {"id": "MAP-2", "name": "Stakeholder Analysis", "check": "has_agents", "weight": 1},
            {"id": "MEASURE-1", "name": "Risk Metrics", "check": "has_defences", "weight": 2},
            {"id": "MEASURE-2", "name": "Testing Coverage", "check": "has_policies", "weight": 2},
            {"id": "MANAGE-1", "name": "Incident Response", "check": "has_topology", "weight": 2},
            {"id": "GOVERN-1", "name": "Accountability", "check": "has_agents", "weight": 1},
        ],
        ComplianceFramework.EU_AI_ACT: [
            {"id": "ART-9", "name": "Risk Management System", "check": "has_defences", "weight": 2},
            {"id": "ART-10", "name": "Data Governance", "check": "has_policies", "weight": 2},
            {"id": "ART-11", "name": "Technical Documentation", "check": "has_description", "weight": 1},
            {"id": "ART-13", "name": "Transparency", "check": "has_agents", "weight": 1},
            {"id": "ART-14", "name": "Human Oversight", "check": "has_topology", "weight": 2},
            {"id": "ART-15", "name": "Accuracy & Robustness", "check": "has_defences", "weight": 2},
        ],
        ComplianceFramework.ISO_42001: [
            {"id": "6.1", "name": "Risk Assessment", "check": "has_defences", "weight": 2},
            {"id": "6.2", "name": "AI Objectives", "check": "has_description", "weight": 1},
            {"id": "7.1", "name": "Resources", "check": "has_agents", "weight": 1},
            {"id": "8.1", "name": "Operational Planning", "check": "has_topology", "weight": 2},
            {"id": "9.1", "name": "Monitoring", "check": "has_policies", "weight": 2},
            {"id": "10.1", "name": "Improvement", "check": "has_defences", "weight": 1},
        ],
    }

    framework_controls = controls.get(framework, controls[ComplianceFramework.NIST_AI_RMF])
    findings: list[dict[str, Any]] = []
    total_weight = 0
    achieved_weight = 0

    for ctrl in framework_controls:
        check = ctrl["check"]
        weight = ctrl["weight"]
        total_weight += weight

        passed = False
        if check == "has_description":
            passed = len(twin.description) > 10
        elif check == "has_agents":
            passed = len(twin.agents) >= 1
        elif check == "has_defences":
            passed = len(twin.defences) >= 2
        elif check == "has_policies":
            passed = len(twin.policies) >= 1
        elif check == "has_topology":
            passed = len(twin.topology) >= 1
        else:
            passed = random.random() > 0.4

        if passed:
            achieved_weight += weight

        findings.append({
            "control_id": ctrl["id"],
            "control_name": ctrl["name"],
            "verdict": "pass" if passed else "fail",
            "weight": weight,
            "recommendation": "" if passed else f"Implement {ctrl['name']} controls",
        })

    score = round(achieved_weight / total_weight * 100, 1) if total_weight else 0.0

    return {
        "framework": framework.value,
        "twin_id": twin.id,
        "overall_score": score,
        "verdict": "pass" if score >= 70 else ("warning" if score >= 50 else "fail"),
        "controls_evaluated": len(findings),
        "controls_passed": sum(1 for f in findings if f["verdict"] == "pass"),
        "controls_failed": sum(1 for f in findings if f["verdict"] == "fail"),
        "findings": findings,
        "timestamp": _now().isoformat(),
    }


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    agents = [
        AgentSpec(name="planner-01", agent_type="planner", model="gpt-4", tools=["search", "calendar"],
                  defences=["input_filter", "rate_limiter"]),
        AgentSpec(name="executor-01", agent_type="executor", model="gpt-4-turbo", tools=["code_exec", "file_write"],
                  defences=["tool_sandbox", "output_validator"]),
        AgentSpec(name="retriever-01", agent_type="retriever", model="gpt-3.5-turbo", tools=["vector_search", "web_scrape"],
                  defences=["memory_guard", "input_filter"]),
        AgentSpec(name="evaluator-01", agent_type="evaluator", model="gpt-4", tools=["scoring"],
                  defences=["output_validator"]),
    ]

    topology = {
        "planner-01": ["executor-01", "retriever-01"],
        "retriever-01": ["executor-01"],
        "executor-01": ["evaluator-01"],
    }

    policies = [
        {"name": "min-defences", "type": "guardrail_check", "rules": [
            {"check": "min_defences", "min": 3}
        ]},
        {"name": "no-external-agents", "type": "access_control", "rules": [
            {"check": "no_direct_external"}
        ]},
    ]

    twin = TwinDefinition(
        name="Production AI Stack — Replica",
        description="Digital twin of the production multi-agent AI pipeline "
                    "including planner, executor, retriever, and evaluator agents "
                    "with defence guardrails and topology constraints.",
        agents=agents,
        defences=["input_filter", "output_validator", "tool_sandbox", "memory_guard", "rate_limiter"],
        topology=topology,
        policies=policies,
    )
    TWINS[twin.id] = twin
    _take_snapshot(twin)


_seed()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "ave-digital-twin",
        "version": "1.0.0",
        "twins": len(TWINS),
        "snapshots": len(SNAPSHOTS),
        "exercises": len(EXERCISES),
    }


# ---- Twin CRUD -----------------------------------------------------------

@app.post("/v1/twins", status_code=status.HTTP_201_CREATED)
async def create_twin(data: TwinCreate):
    twin = TwinDefinition(
        name=data.name,
        description=data.description,
        agents=data.agents,
        defences=data.defences,
        topology=data.topology,
        policies=data.policies,
    )
    TWINS[twin.id] = twin
    snap = _take_snapshot(twin)
    return {"id": twin.id, "name": twin.name, "snapshot_id": snap.id}


@app.get("/v1/twins")
async def list_twins():
    return {
        "count": len(TWINS),
        "twins": [
            {
                "id": t.id,
                "name": t.name,
                "agents": len(t.agents),
                "defences": len(t.defences),
                "status": t.status.value,
                "version": t.version,
                "created_at": t.created_at,
            }
            for t in TWINS.values()
        ],
    }


@app.get("/v1/twins/{twin_id}")
async def get_twin(twin_id: str):
    if twin_id not in TWINS:
        raise HTTPException(404, "Twin not found")
    return TWINS[twin_id].dict()


# ---- Snapshots -----------------------------------------------------------

@app.post("/v1/twins/{twin_id}/snapshot", status_code=status.HTTP_201_CREATED)
async def take_snapshot(twin_id: str):
    if twin_id not in TWINS:
        raise HTTPException(404, "Twin not found")
    twin = TWINS[twin_id]
    snap = _take_snapshot(twin)
    return {"id": snap.id, "state_hash": snap.state_hash, "version": snap.version}


@app.get("/v1/twins/{twin_id}/snapshots")
async def list_snapshots(twin_id: str):
    if twin_id not in TWINS:
        raise HTTPException(404, "Twin not found")
    snaps = [SNAPSHOTS[sid] for sid in TWINS[twin_id].snapshots if sid in SNAPSHOTS]
    return {
        "count": len(snaps),
        "snapshots": [
            {
                "id": s.id,
                "version": s.version,
                "state_hash": s.state_hash,
                "agents": s.agent_count,
                "defences": s.defence_count,
                "taken_at": s.taken_at,
            }
            for s in snaps
        ],
    }


# ---- Diff ----------------------------------------------------------------

@app.get("/v1/twins/{twin_id}/diff")
async def diff_snapshots(
    twin_id: str,
    snapshot_a: str = Query(...),
    snapshot_b: str = Query(...),
):
    if twin_id not in TWINS:
        raise HTTPException(404, "Twin not found")
    if snapshot_a not in SNAPSHOTS:
        raise HTTPException(404, f"Snapshot {snapshot_a} not found")
    if snapshot_b not in SNAPSHOTS:
        raise HTTPException(404, f"Snapshot {snapshot_b} not found")

    return _diff_snapshots(SNAPSHOTS[snapshot_a], SNAPSHOTS[snapshot_b]).dict()


# ---- Exercises -----------------------------------------------------------

@app.post("/v1/exercises", status_code=status.HTTP_201_CREATED)
async def create_exercise(data: ExerciseCreate):
    if data.twin_id not in TWINS:
        raise HTTPException(404, "Twin not found")
    for cat in data.attack_categories:
        if cat not in AVE_CATEGORIES:
            raise HTTPException(400, f"Invalid attack category: {cat}")

    twin = TWINS[data.twin_id]
    ex = Exercise(
        twin_id=data.twin_id,
        exercise_type=data.exercise_type,
        attack_categories=data.attack_categories,
        rounds=data.rounds,
        intensity=data.intensity,
        status=ExerciseStatus.RUNNING,
    )

    result = _run_exercise(twin, ex)
    ex.results = result["rounds"]
    ex.summary = result["summary"]
    ex.status = ExerciseStatus.COMPLETED
    ex.completed_at = _now().isoformat()

    EXERCISES[ex.id] = ex
    return {
        "id": ex.id,
        "exercise_type": ex.exercise_type.value,
        "status": ex.status.value,
        "summary": ex.summary,
    }


@app.get("/v1/exercises")
async def list_exercises(twin_id: Optional[str] = None):
    exs = list(EXERCISES.values())
    if twin_id:
        exs = [e for e in exs if e.twin_id == twin_id]
    return {
        "count": len(exs),
        "exercises": [
            {
                "id": e.id,
                "twin_id": e.twin_id,
                "type": e.exercise_type.value,
                "status": e.status.value,
                "rounds": e.rounds,
                "defence_rate": e.summary.get("defence_rate", 0),
                "completed_at": e.completed_at,
            }
            for e in exs
        ],
    }


@app.get("/v1/exercises/{ex_id}")
async def get_exercise(ex_id: str):
    if ex_id not in EXERCISES:
        raise HTTPException(404, "Exercise not found")
    return EXERCISES[ex_id].dict()


# ---- Policy Test ---------------------------------------------------------

@app.post("/v1/twins/{twin_id}/policy-test")
async def test_policy(twin_id: str, policy: PolicyTest):
    if twin_id not in TWINS:
        raise HTTPException(404, "Twin not found")
    return _policy_test(TWINS[twin_id], policy)


# ---- Compliance Audit ----------------------------------------------------

@app.post("/v1/twins/{twin_id}/compliance-audit")
async def compliance_audit(twin_id: str, req: ComplianceAuditRequest):
    if twin_id not in TWINS:
        raise HTTPException(404, "Twin not found")
    return _compliance_audit(TWINS[twin_id], req.framework)


# ---- Analytics -----------------------------------------------------------

@app.get("/v1/analytics")
async def twin_analytics():
    twins = list(TWINS.values())
    exs = list(EXERCISES.values())

    total_agents = sum(len(t.agents) for t in twins)
    total_defences = sum(len(t.defences) for t in twins)
    by_ex_type = Counter(e.exercise_type.value for e in exs)

    defence_rates = [e.summary.get("defence_rate", 0) for e in exs if e.summary]
    avg_defence_rate = round(statistics.mean(defence_rates), 4) if defence_rates else 0.0

    return {
        "total_twins": len(twins),
        "total_agents": total_agents,
        "total_defences": total_defences,
        "total_snapshots": len(SNAPSHOTS),
        "total_exercises": len(exs),
        "by_exercise_type": dict(by_ex_type),
        "avg_defence_rate": avg_defence_rate,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8802)
