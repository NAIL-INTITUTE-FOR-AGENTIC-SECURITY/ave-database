"""Recovery Orchestrator — Phase 28 Service 2 · Port 9916"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random
from collections import deque

app = FastAPI(title="Recovery Orchestrator", version="0.28.2")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class SystemType(str, Enum):
    application = "application"
    database = "database"
    cache = "cache"
    message_queue = "message_queue"
    load_balancer = "load_balancer"
    ai_service = "ai_service"

class ScenarioType(str, Enum):
    region_outage = "region_outage"
    database_corruption = "database_corruption"
    network_partition = "network_partition"
    ransomware = "ransomware"
    cascading_failure = "cascading_failure"
    data_centre_loss = "data_centre_loss"
    key_compromise = "key_compromise"

class RecoveryState(str, Enum):
    initiated = "initiated"
    assessing = "assessing"
    sequencing = "sequencing"
    restoring = "restoring"
    verifying = "verifying"
    completed = "completed"
    failed = "failed"

REC_TRANSITIONS = {
    "initiated": ["assessing"],
    "assessing": ["sequencing"],
    "sequencing": ["restoring"],
    "restoring": ["verifying"],
    "verifying": ["completed", "failed"],
}

class VerificationType(str, Enum):
    health_check = "health_check"
    data_integrity = "data_integrity"
    functional_test = "functional_test"

class VerificationResult(str, Enum):
    passed = "pass"
    failed = "fail"
    degraded = "degraded"

# ── Models ───────────────────────────────────────────────────────────
class SystemCreate(BaseModel):
    name: str
    system_type: SystemType
    recovery_priority: int = Field(5, ge=1, le=10)
    depends_on: list[str] = []
    rto_minutes: int = Field(60, ge=1)
    rpo_minutes: int = Field(15, ge=1)
    backup_available: bool = True

class PlanCreate(BaseModel):
    name: str
    scenario: ScenarioType
    target_system_ids: list[str] = []
    description: str = ""

class RecoveryCreate(BaseModel):
    plan_id: str
    triggered_by: str = "manual"
    affected_system_ids: list[str] = []

class VerificationSubmit(BaseModel):
    verification_type: VerificationType
    result: VerificationResult
    details: str = ""

# ── Stores ───────────────────────────────────────────────────────────
systems: dict[str, dict] = {}
plans: dict[str, dict] = {}
recoveries: dict[str, dict] = {}

def _now():
    return datetime.now(timezone.utc).isoformat()

# ── Dependency Sequencing ────────────────────────────────────────────
def _topological_sort(system_ids: list[str]) -> tuple[list[str], list[str]]:
    """Return (ordered_ids, circular_warnings)."""
    subset = {sid: systems[sid] for sid in system_ids if sid in systems}
    in_degree = {sid: 0 for sid in subset}
    adj: dict[str, list[str]] = {sid: [] for sid in subset}

    for sid, s in subset.items():
        for dep in s["depends_on"]:
            if dep in subset:
                adj[dep].append(sid)
                in_degree[sid] += 1

    queue = deque(sorted(
        [sid for sid, d in in_degree.items() if d == 0],
        key=lambda s: systems[s]["recovery_priority"],
        reverse=True,
    ))
    ordered = []
    while queue:
        current = queue.popleft()
        ordered.append(current)
        for neighbor in adj[current]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    circulars = [sid for sid in subset if sid not in ordered]
    return ordered, circulars

def _compute_confidence(recovery: dict) -> dict:
    """Compute progressive confidence score."""
    total = len(recovery["affected_system_ids"])
    if total == 0:
        return {"score": 0, "verified": 0, "total": 0, "trend": "n/a"}

    verified = sum(1 for v in recovery["verifications"].values() if v["result"] == "pass")
    degraded = sum(1 for v in recovery["verifications"].values() if v["result"] == "degraded")
    failed = sum(1 for v in recovery["verifications"].values() if v["result"] == "fail")

    score = round((verified * 100 + degraded * 50) / total, 1)
    timeline = recovery.get("confidence_timeline", [])

    trend = "stable"
    if len(timeline) >= 2:
        trend = "rising" if timeline[-1]["score"] > timeline[-2]["score"] else "declining" if timeline[-1]["score"] < timeline[-2]["score"] else "stable"

    return {"score": score, "verified": verified, "degraded": degraded, "failed": failed, "total": total, "trend": trend}

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "recovery-orchestrator",
        "status": "healthy",
        "version": "0.28.2",
        "systems": len(systems),
        "plans": len(plans),
        "active_recoveries": sum(1 for r in recoveries.values() if r["state"] not in ("completed", "failed")),
    }

# ── Systems ──────────────────────────────────────────────────────────
@app.post("/v1/systems", status_code=201)
def create_system(body: SystemCreate):
    for dep in body.depends_on:
        if dep not in systems:
            raise HTTPException(404, f"Dependency system {dep} not found")
    sid = str(uuid.uuid4())
    rec = {"id": sid, **body.model_dump(), "created_at": _now()}
    systems[sid] = rec
    return rec

@app.get("/v1/systems")
def list_systems(system_type: Optional[SystemType] = None):
    out = list(systems.values())
    if system_type:
        out = [s for s in out if s["system_type"] == system_type]
    return sorted(out, key=lambda s: s["recovery_priority"], reverse=True)

@app.get("/v1/systems/{sid}")
def get_system(sid: str):
    if sid not in systems:
        raise HTTPException(404, "System not found")
    s = systems[sid]
    dependents = [oid for oid, o in systems.items() if sid in o["depends_on"]]
    return {**s, "dependents": dependents}

# ── Plans ────────────────────────────────────────────────────────────
@app.post("/v1/plans", status_code=201)
def create_plan(body: PlanCreate):
    for sid in body.target_system_ids:
        if sid not in systems:
            raise HTTPException(404, f"System {sid} not found")
    pid = str(uuid.uuid4())
    sequence, circulars = _topological_sort(body.target_system_ids)
    rec = {
        "id": pid,
        **body.model_dump(),
        "recovery_sequence": sequence,
        "circular_dependency_warnings": circulars,
        "estimated_total_minutes": sum(systems[sid]["rto_minutes"] for sid in body.target_system_ids if sid in systems),
        "created_at": _now(),
    }
    plans[pid] = rec
    return rec

@app.get("/v1/plans")
def list_plans(scenario: Optional[ScenarioType] = None):
    out = list(plans.values())
    if scenario:
        out = [p for p in out if p["scenario"] == scenario]
    return out

# ── Recoveries ───────────────────────────────────────────────────────
@app.post("/v1/recoveries", status_code=201)
def create_recovery(body: RecoveryCreate):
    if body.plan_id not in plans:
        raise HTTPException(404, "Plan not found")
    plan = plans[body.plan_id]
    affected = body.affected_system_ids or plan["target_system_ids"]
    sequence, circulars = _topological_sort(affected)

    rid = str(uuid.uuid4())
    rec = {
        "id": rid,
        "plan_id": body.plan_id,
        "scenario": plan["scenario"],
        "triggered_by": body.triggered_by,
        "affected_system_ids": affected,
        "recovery_sequence": sequence,
        "circular_dependency_warnings": circulars,
        "state": "initiated",
        "verifications": {},
        "confidence_timeline": [],
        "communication_log": [{"timestamp": _now(), "message": f"Recovery initiated for {plan['scenario']} scenario"}],
        "rto_breaches": [],
        "started_at": _now(),
        "completed_at": None,
    }
    recoveries[rid] = rec
    return rec

@app.get("/v1/recoveries")
def list_recoveries(state: Optional[RecoveryState] = None):
    out = list(recoveries.values())
    if state:
        out = [r for r in out if r["state"] == state]
    return out

@app.get("/v1/recoveries/{rid}")
def get_recovery(rid: str):
    if rid not in recoveries:
        raise HTTPException(404, "Recovery not found")
    r = recoveries[rid]
    r["confidence"] = _compute_confidence(r)
    return r

@app.patch("/v1/recoveries/{rid}/advance")
def advance_recovery(rid: str, target_state: RecoveryState = Query(...)):
    if rid not in recoveries:
        raise HTTPException(404, "Recovery not found")
    r = recoveries[rid]
    allowed = REC_TRANSITIONS.get(r["state"], [])
    if target_state not in allowed:
        raise HTTPException(400, f"Cannot transition from {r['state']} to {target_state}")
    r["state"] = target_state
    r["communication_log"].append({"timestamp": _now(), "message": f"Recovery advanced to {target_state}"})
    if target_state in ("completed", "failed"):
        r["completed_at"] = _now()
    return r

# ── Verify System ────────────────────────────────────────────────────
@app.post("/v1/recoveries/{rid}/verify/{sid}")
def verify_system(rid: str, sid: str, body: VerificationSubmit):
    if rid not in recoveries:
        raise HTTPException(404, "Recovery not found")
    if sid not in systems:
        raise HTTPException(404, "System not found")
    r = recoveries[rid]
    r["verifications"][sid] = {
        "system_id": sid,
        "system_name": systems[sid]["name"],
        **body.model_dump(),
        "verified_at": _now(),
    }
    conf = _compute_confidence(r)
    r["confidence_timeline"].append({"timestamp": _now(), "score": conf["score"]})
    r["communication_log"].append({"timestamp": _now(), "message": f"System {systems[sid]['name']} verified: {body.result}"})
    return {"verification": r["verifications"][sid], "confidence": conf}

# ── Sequence ─────────────────────────────────────────────────────────
@app.get("/v1/recoveries/{rid}/sequence")
def get_sequence(rid: str):
    if rid not in recoveries:
        raise HTTPException(404, "Recovery not found")
    r = recoveries[rid]
    steps = []
    for i, sid in enumerate(r["recovery_sequence"]):
        s = systems.get(sid, {})
        steps.append({
            "order": i + 1,
            "system_id": sid,
            "system_name": s.get("name", "unknown"),
            "system_type": s.get("system_type", "unknown"),
            "recovery_priority": s.get("recovery_priority", 0),
            "rto_minutes": s.get("rto_minutes", 0),
            "depends_on": s.get("depends_on", []),
            "verified": sid in r["verifications"],
            "verification_result": r["verifications"].get(sid, {}).get("result", "pending"),
        })
    return {"recovery_id": rid, "steps": steps, "circular_warnings": r["circular_dependency_warnings"]}

# ── Confidence ───────────────────────────────────────────────────────
@app.get("/v1/recoveries/{rid}/confidence")
def get_confidence(rid: str):
    if rid not in recoveries:
        raise HTTPException(404, "Recovery not found")
    r = recoveries[rid]
    return {"recovery_id": rid, "current": _compute_confidence(r), "timeline": r["confidence_timeline"]}

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    rl = list(recoveries.values())
    completed = [r for r in rl if r["state"] == "completed"]
    failed = [r for r in rl if r["state"] == "failed"]
    by_scenario = {}
    for r in rl:
        by_scenario[r["scenario"]] = by_scenario.get(r["scenario"], 0) + 1
    by_state = {}
    for r in rl:
        by_state[r["state"]] = by_state.get(r["state"], 0) + 1
    avg_confidence = 0
    if completed:
        avg_confidence = round(sum(_compute_confidence(r)["score"] for r in completed) / len(completed), 1)
    return {
        "total_systems": len(systems),
        "total_plans": len(plans),
        "total_recoveries": len(rl),
        "by_state": by_state,
        "by_scenario": by_scenario,
        "completed": len(completed),
        "failed": len(failed),
        "success_rate": round(len(completed) / max(len(completed) + len(failed), 1), 3),
        "avg_final_confidence": avg_confidence,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9916)
