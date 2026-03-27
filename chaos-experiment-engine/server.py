"""Chaos Experiment Engine — Phase 28 Service 1 · Port 9915"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random, time

app = FastAPI(title="Chaos Experiment Engine", version="0.28.1")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class TargetType(str, Enum):
    service = "service"
    database = "database"
    network = "network"
    compute = "compute"
    storage = "storage"
    ai_pipeline = "ai_pipeline"

class FaultType(str, Enum):
    latency_injection = "latency_injection"
    cpu_stress = "cpu_stress"
    memory_pressure = "memory_pressure"
    disk_fill = "disk_fill"
    network_partition = "network_partition"
    process_kill = "process_kill"
    dependency_failure = "dependency_failure"
    data_corruption = "data_corruption"

class ContainmentLevel(str, Enum):
    single_instance = "single_instance"
    service_subset = "service_subset"
    full_service = "full_service"

CONTAINMENT_BLAST = {"single_instance": 0.1, "service_subset": 0.4, "full_service": 1.0}

class ExperimentState(str, Enum):
    designed = "designed"
    approved = "approved"
    preparing = "preparing"
    running = "running"
    observing = "observing"
    analysing = "analysing"
    completed = "completed"
    aborted = "aborted"

EXP_TRANSITIONS = {
    "designed": ["approved"],
    "approved": ["preparing"],
    "preparing": ["running", "aborted"],
    "running": ["observing", "aborted"],
    "observing": ["analysing", "aborted"],
    "analysing": ["completed"],
}

class RollbackStrategy(str, Enum):
    automatic = "automatic"
    manual = "manual"
    progressive = "progressive"

class ExperimentOutcome(str, Enum):
    passed = "passed"
    degraded = "degraded"
    failed = "failed"

# ── Models ───────────────────────────────────────────────────────────
class TargetCreate(BaseModel):
    name: str
    target_type: TargetType
    criticality: int = Field(5, ge=1, le=10)
    baseline_error_rate: float = Field(0.01, ge=0, le=1)
    baseline_latency_p99_ms: float = Field(200, ge=0)

class ExperimentCreate(BaseModel):
    name: str
    target_id: str
    fault_type: FaultType
    containment_level: ContainmentLevel = ContainmentLevel.single_instance
    duration_seconds: int = Field(60, ge=10, le=3600)
    max_impact_percentage: float = Field(20, ge=1, le=100)
    abort_threshold_error_rate: float = Field(0.5, ge=0, le=1)
    rollback_strategy: RollbackStrategy = RollbackStrategy.automatic
    steady_state_hypothesis: str = "System maintains error rate < 5% and latency p99 < 500ms"

# ── Stores ───────────────────────────────────────────────────────────
targets: dict[str, dict] = {}
experiments: dict[str, dict] = {}
cooldown_until: float = 0.0  # epoch timestamp

def _now():
    return datetime.now(timezone.utc).isoformat()

def _sim_observations(exp: dict, target: dict) -> dict:
    """Simulate experiment observations."""
    fault = exp["fault_type"]
    containment = CONTAINMENT_BLAST.get(exp["containment_level"], 0.5)
    severity = containment * random.uniform(0.5, 1.5)

    base_err = target["baseline_error_rate"]
    base_lat = target["baseline_latency_p99_ms"]

    # Fault-type-specific impact simulation
    err_mult = {"latency_injection": 1.2, "cpu_stress": 2.0, "memory_pressure": 3.0,
                "disk_fill": 1.5, "network_partition": 5.0, "process_kill": 8.0,
                "dependency_failure": 4.0, "data_corruption": 2.5}
    lat_mult = {"latency_injection": 5.0, "cpu_stress": 3.0, "memory_pressure": 2.0,
                "disk_fill": 1.5, "network_partition": 10.0, "process_kill": 0,
                "dependency_failure": 4.0, "data_corruption": 1.2}

    observed_err = min(1.0, base_err * err_mult.get(fault, 2.0) * severity)
    observed_lat = base_lat * lat_mult.get(fault, 2.0) * severity
    recovery_time_s = random.uniform(5, 120) * containment
    cascade_depth = random.randint(0, 3) if severity > 0.7 else 0

    return {
        "baseline_error_rate": base_err,
        "observed_error_rate": round(observed_err, 4),
        "error_rate_increase": round((observed_err - base_err) / max(base_err, 0.001) * 100, 1),
        "baseline_latency_p99_ms": base_lat,
        "observed_latency_p99_ms": round(observed_lat, 1),
        "latency_increase_pct": round((observed_lat - base_lat) / max(base_lat, 1) * 100, 1),
        "recovery_time_seconds": round(recovery_time_s, 1),
        "cascade_depth": cascade_depth,
        "containment_held": severity < 0.9,
        "abort_triggered": observed_err > exp["abort_threshold_error_rate"],
    }

def _determine_outcome(obs: dict) -> ExperimentOutcome:
    if obs["abort_triggered"]:
        return "failed"
    if obs["error_rate_increase"] > 100 or obs["cascade_depth"] > 1:
        return "degraded"
    return "passed"

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "chaos-experiment-engine",
        "status": "healthy",
        "version": "0.28.1",
        "targets": len(targets),
        "experiments": len(experiments),
    }

# ── Targets ──────────────────────────────────────────────────────────
@app.post("/v1/targets", status_code=201)
def create_target(body: TargetCreate):
    tid = str(uuid.uuid4())
    rec = {"id": tid, **body.model_dump(), "created_at": _now()}
    targets[tid] = rec
    return rec

@app.get("/v1/targets")
def list_targets(target_type: Optional[TargetType] = None):
    out = list(targets.values())
    if target_type:
        out = [t for t in out if t["target_type"] == target_type]
    return out

# ── Experiments ──────────────────────────────────────────────────────
@app.post("/v1/experiments", status_code=201)
def create_experiment(body: ExperimentCreate):
    if body.target_id not in targets:
        raise HTTPException(404, "Target not found")
    eid = str(uuid.uuid4())
    rec = {
        "id": eid,
        **body.model_dump(),
        "state": "designed",
        "observations": None,
        "outcome": None,
        "findings": [],
        "rollback_executed": False,
        "created_at": _now(),
        "started_at": None,
        "completed_at": None,
    }
    experiments[eid] = rec
    return rec

@app.get("/v1/experiments")
def list_experiments(state: Optional[ExperimentState] = None, fault_type: Optional[FaultType] = None):
    out = list(experiments.values())
    if state:
        out = [e for e in out if e["state"] == state]
    if fault_type:
        out = [e for e in out if e["fault_type"] == fault_type]
    return out

@app.get("/v1/experiments/{eid}")
def get_experiment(eid: str):
    if eid not in experiments:
        raise HTTPException(404, "Experiment not found")
    return experiments[eid]

@app.patch("/v1/experiments/{eid}/advance")
def advance_experiment(eid: str, target_state: ExperimentState = Query(...)):
    if eid not in experiments:
        raise HTTPException(404, "Experiment not found")
    e = experiments[eid]
    allowed = EXP_TRANSITIONS.get(e["state"], [])
    if target_state not in allowed:
        raise HTTPException(400, f"Cannot transition from {e['state']} to {target_state}")
    e["state"] = target_state
    return e

# ── Run ──────────────────────────────────────────────────────────────
@app.post("/v1/experiments/{eid}/run")
def run_experiment(eid: str):
    global cooldown_until
    if eid not in experiments:
        raise HTTPException(404, "Experiment not found")
    e = experiments[eid]
    if e["state"] not in ("designed", "approved", "preparing"):
        raise HTTPException(400, f"Cannot run experiment in state {e['state']}")

    # Cooldown check
    if time.time() < cooldown_until:
        raise HTTPException(429, "Cooldown period active — wait before running another experiment")

    target = targets.get(e["target_id"])
    if not target:
        raise HTTPException(404, "Target not found")

    # Pre-flight safety
    if target["criticality"] >= 9 and e["containment_level"] == "full_service":
        raise HTTPException(400, "Safety guard: full_service containment blocked for criticality >= 9 targets")

    # Simulate
    e["state"] = "running"
    e["started_at"] = _now()
    obs = _sim_observations(e, target)
    e["observations"] = obs
    outcome = _determine_outcome(obs)
    e["outcome"] = outcome

    # Auto-rollback on failure
    if outcome == "failed" and e["rollback_strategy"] == "automatic":
        e["rollback_executed"] = True

    # Generate findings
    findings = []
    if outcome == "passed":
        findings.append({"type": "positive", "message": f"System resilient to {e['fault_type']} at {e['containment_level']} level", "severity": "info"})
    if outcome == "degraded":
        findings.append({"type": "warning", "message": f"Partial degradation observed — error rate increased {obs['error_rate_increase']}%", "severity": "medium"})
        findings.append({"type": "recommendation", "message": "Add circuit breaker or retry logic", "severity": "medium"})
    if outcome == "failed":
        findings.append({"type": "failure", "message": f"Cascading failure — abort threshold breached (error rate: {obs['observed_error_rate']})", "severity": "critical"})
        findings.append({"type": "recommendation", "message": "Implement bulkhead pattern and dependency timeout", "severity": "high"})
    if obs["cascade_depth"] > 0:
        findings.append({"type": "warning", "message": f"Cascade propagation detected — depth {obs['cascade_depth']}", "severity": "high"})

    e["findings"] = findings
    e["state"] = "completed" if outcome != "failed" else "aborted"
    e["completed_at"] = _now()

    # Set cooldown (60 seconds)
    cooldown_until = time.time() + 60

    return e

# ── Abort ────────────────────────────────────────────────────────────
@app.post("/v1/experiments/{eid}/abort")
def abort_experiment(eid: str, reason: str = ""):
    if eid not in experiments:
        raise HTTPException(404, "Experiment not found")
    e = experiments[eid]
    if e["state"] in ("completed", "aborted"):
        raise HTTPException(400, "Experiment already finished")
    e["state"] = "aborted"
    e["completed_at"] = _now()
    e["findings"].append({"type": "abort", "message": f"Manually aborted: {reason or 'no reason given'}", "severity": "info"})
    return e

# ── Rollback ─────────────────────────────────────────────────────────
@app.post("/v1/experiments/{eid}/rollback")
def rollback_experiment(eid: str):
    if eid not in experiments:
        raise HTTPException(404, "Experiment not found")
    e = experiments[eid]
    if e["rollback_executed"]:
        raise HTTPException(400, "Rollback already executed")
    e["rollback_executed"] = True
    e["findings"].append({"type": "rollback", "message": f"Manual rollback executed ({e['rollback_strategy']} strategy)", "severity": "info"})
    return e

# ── Observations ─────────────────────────────────────────────────────
@app.get("/v1/experiments/{eid}/observations")
def get_observations(eid: str):
    if eid not in experiments:
        raise HTTPException(404, "Experiment not found")
    e = experiments[eid]
    if not e["observations"]:
        raise HTTPException(400, "No observations — experiment has not been run")
    return {
        "experiment_id": eid,
        "fault_type": e["fault_type"],
        "containment_level": e["containment_level"],
        "observations": e["observations"],
        "outcome": e["outcome"],
        "steady_state_hypothesis": e["steady_state_hypothesis"],
        "hypothesis_validated": e["outcome"] == "passed",
    }

# ── Safety Status ────────────────────────────────────────────────────
@app.get("/v1/safety-status")
def safety_status():
    running = sum(1 for e in experiments.values() if e["state"] == "running")
    cooldown_remaining = max(0, cooldown_until - time.time())
    return {
        "experiments_running": running,
        "cooldown_active": cooldown_remaining > 0,
        "cooldown_remaining_seconds": round(cooldown_remaining, 1),
        "high_criticality_targets": sum(1 for t in targets.values() if t["criticality"] >= 8),
        "total_aborts": sum(1 for e in experiments.values() if e["state"] == "aborted"),
        "safety_guards_triggered": sum(1 for e in experiments.values() if e.get("observations", {}) and isinstance(e.get("observations"), dict) and e["observations"].get("abort_triggered", False)),
    }

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    el = list(experiments.values())
    completed = [e for e in el if e["state"] == "completed"]
    aborted = [e for e in el if e["state"] == "aborted"]
    by_fault = {}
    for e in el:
        by_fault[e["fault_type"]] = by_fault.get(e["fault_type"], 0) + 1
    by_outcome = {}
    for e in el:
        if e["outcome"]:
            by_outcome[e["outcome"]] = by_outcome.get(e["outcome"], 0) + 1
    by_state = {}
    for e in el:
        by_state[e["state"]] = by_state.get(e["state"], 0) + 1
    avg_recovery = 0
    obs_with_recovery = [e["observations"]["recovery_time_seconds"] for e in completed if e.get("observations")]
    if obs_with_recovery:
        avg_recovery = round(sum(obs_with_recovery) / len(obs_with_recovery), 1)
    return {
        "total_targets": len(targets),
        "total_experiments": len(el),
        "by_state": by_state,
        "by_fault_type": by_fault,
        "by_outcome": by_outcome,
        "completed": len(completed),
        "aborted": len(aborted),
        "pass_rate": round(sum(1 for e in completed if e["outcome"] == "passed") / max(len(completed), 1), 3),
        "avg_recovery_time_seconds": avg_recovery,
        "total_rollbacks": sum(1 for e in el if e["rollback_executed"]),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9915)
