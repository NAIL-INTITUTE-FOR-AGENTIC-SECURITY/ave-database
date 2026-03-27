"""Knowledge Distillation Engine — Phase 29 Service 5 · Port 9924"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random

app = FastAPI(title="Knowledge Distillation Engine", version="0.29.5")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class TeacherType(str, Enum):
    large_llm = "large_llm"
    ensemble = "ensemble"
    deep_classifier = "deep_classifier"
    transformer = "transformer"
    graph_neural_net = "graph_neural_net"
    multi_modal = "multi_modal"

class TargetPlatform(str, Enum):
    edge = "edge"
    cloud = "cloud"
    mobile = "mobile"

class DistillMethod(str, Enum):
    logit_matching = "logit_matching"
    feature_mimicry = "feature_mimicry"
    attention_transfer = "attention_transfer"
    contrastive = "contrastive"
    progressive = "progressive"

class JobState(str, Enum):
    configured = "configured"
    distilling = "distilling"
    evaluating = "evaluating"
    validated = "validated"
    deployed = "deployed"
    rejected = "rejected"

JOB_TRANSITIONS = {
    "configured": ["distilling"],
    "distilling": ["evaluating"],
    "evaluating": ["validated", "rejected"],
    "validated": ["deployed"],
}

# ── Models ───────────────────────────────────────────────────────────
class TeacherCreate(BaseModel):
    name: str
    teacher_type: TeacherType
    parameter_count: int = Field(1_000_000, ge=1000)
    accuracy_baseline: float = Field(0.92, ge=0, le=1)
    latency_ms: float = Field(150, ge=1)
    memory_mb: float = Field(2048, ge=1)

class StudentCreate(BaseModel):
    name: str
    max_parameters: int = Field(100_000, ge=1000)
    max_latency_ms: float = Field(20, ge=1)
    target_platform: TargetPlatform = TargetPlatform.edge
    description: str = ""

class JobCreate(BaseModel):
    teacher_id: str
    student_id: str
    method: DistillMethod
    temperature: float = Field(3.0, ge=1, le=20)
    alpha: float = Field(0.7, ge=0, le=1)
    min_accuracy_retention_pct: float = Field(90, ge=50, le=100)
    security_boundary_tolerance: float = Field(0.02, ge=0, le=0.2)

# ── Stores ───────────────────────────────────────────────────────────
teachers: dict[str, dict] = {}
students: dict[str, dict] = {}
jobs: dict[str, dict] = {}

def _now():
    return datetime.now(timezone.utc).isoformat()

def _sim_distillation(teacher: dict, student: dict, job: dict) -> dict:
    """Simulate distillation results."""
    method = job["method"]
    temp = job["temperature"]
    alpha = job["alpha"]

    # Method-specific retention factors
    method_retention = {
        "logit_matching": 0.88, "feature_mimicry": 0.91, "attention_transfer": 0.93,
        "contrastive": 0.90, "progressive": 0.94,
    }
    base_retention = method_retention.get(method, 0.90)

    # Temperature and alpha adjustments
    temp_bonus = min(0.05, (temp - 1) * 0.005)
    alpha_bonus = alpha * 0.03
    retention = min(0.99, base_retention + temp_bonus + alpha_bonus + random.uniform(-0.03, 0.03))

    param_ratio = student["max_parameters"] / teacher["parameter_count"]
    latency_ratio = student["max_latency_ms"] / teacher["latency_ms"]
    memory_ratio = param_ratio * 1.1  # slightly more than param ratio

    student_accuracy = round(teacher["accuracy_baseline"] * retention, 4)
    student_latency = round(teacher["latency_ms"] * latency_ratio * random.uniform(0.8, 1.2), 1)
    student_memory = round(teacher["memory_mb"] * memory_ratio * random.uniform(0.8, 1.1), 1)

    # Security boundary fidelity
    boundary_fidelity = round(min(1.0, retention + random.uniform(-0.02, 0.03)), 4)
    boundary_violations = max(0, int((1 - boundary_fidelity) * 100))

    return {
        "student_accuracy": student_accuracy,
        "accuracy_retention_pct": round(student_accuracy / teacher["accuracy_baseline"] * 100, 2),
        "student_latency_ms": student_latency,
        "latency_speedup": round(teacher["latency_ms"] / max(student_latency, 0.1), 2),
        "student_memory_mb": student_memory,
        "memory_reduction_pct": round((1 - student_memory / teacher["memory_mb"]) * 100, 1),
        "parameter_reduction_ratio": round(1 - param_ratio, 4),
        "security_boundary_fidelity": boundary_fidelity,
        "boundary_violations": boundary_violations,
    }

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "knowledge-distillation-engine",
        "status": "healthy",
        "version": "0.29.5",
        "teachers": len(teachers),
        "students": len(students),
        "jobs": len(jobs),
    }

# ── Teachers ─────────────────────────────────────────────────────────
@app.post("/v1/teachers", status_code=201)
def create_teacher(body: TeacherCreate):
    tid = str(uuid.uuid4())
    rec = {"id": tid, **body.model_dump(), "created_at": _now()}
    teachers[tid] = rec
    return rec

@app.get("/v1/teachers")
def list_teachers(teacher_type: Optional[TeacherType] = None):
    out = list(teachers.values())
    if teacher_type:
        out = [t for t in out if t["teacher_type"] == teacher_type]
    return out

# ── Students ─────────────────────────────────────────────────────────
@app.post("/v1/students", status_code=201)
def create_student(body: StudentCreate):
    sid = str(uuid.uuid4())
    rec = {"id": sid, **body.model_dump(), "created_at": _now()}
    students[sid] = rec
    return rec

@app.get("/v1/students")
def list_students(platform: Optional[TargetPlatform] = None):
    out = list(students.values())
    if platform:
        out = [s for s in out if s["target_platform"] == platform]
    return out

# ── Jobs ─────────────────────────────────────────────────────────────
@app.post("/v1/jobs", status_code=201)
def create_job(body: JobCreate):
    if body.teacher_id not in teachers:
        raise HTTPException(404, "Teacher model not found")
    if body.student_id not in students:
        raise HTTPException(404, "Student model not found")
    jid = str(uuid.uuid4())
    rec = {
        "id": jid,
        **body.model_dump(),
        "teacher_name": teachers[body.teacher_id]["name"],
        "student_name": students[body.student_id]["name"],
        "state": "configured",
        "results": None,
        "quality_gates": None,
        "created_at": _now(),
        "completed_at": None,
    }
    jobs[jid] = rec
    return rec

@app.get("/v1/jobs")
def list_jobs(state: Optional[JobState] = None, method: Optional[DistillMethod] = None):
    out = list(jobs.values())
    if state:
        out = [j for j in out if j["state"] == state]
    if method:
        out = [j for j in out if j["method"] == method]
    return out

@app.get("/v1/jobs/{jid}")
def get_job(jid: str):
    if jid not in jobs:
        raise HTTPException(404, "Job not found")
    return jobs[jid]

@app.patch("/v1/jobs/{jid}/advance")
def advance_job(jid: str, target_state: JobState = Query(...)):
    if jid not in jobs:
        raise HTTPException(404, "Job not found")
    j = jobs[jid]
    allowed = JOB_TRANSITIONS.get(j["state"], [])
    if target_state not in allowed:
        raise HTTPException(400, f"Cannot transition from {j['state']} to {target_state}")
    j["state"] = target_state
    if target_state in ("deployed", "rejected"):
        j["completed_at"] = _now()
    return j

# ── Run Distillation ─────────────────────────────────────────────────
@app.post("/v1/jobs/{jid}/run")
def run_distillation(jid: str):
    if jid not in jobs:
        raise HTTPException(404, "Job not found")
    j = jobs[jid]
    if j["state"] != "configured":
        raise HTTPException(400, f"Job must be in configured state, currently {j['state']}")

    teacher = teachers.get(j["teacher_id"])
    student = students.get(j["student_id"])
    if not teacher or not student:
        raise HTTPException(404, "Teacher or student not found")

    # Run simulation
    results = _sim_distillation(teacher, student, j)
    j["results"] = results
    j["state"] = "evaluating"

    # Check quality gates
    acc_gate = results["accuracy_retention_pct"] >= j["min_accuracy_retention_pct"]
    lat_gate = results["student_latency_ms"] <= student["max_latency_ms"]
    sec_gate = (1 - results["security_boundary_fidelity"]) <= j["security_boundary_tolerance"]
    res_gate = results["student_memory_mb"] <= teacher["memory_mb"] * 0.5  # at least 50% reduction

    gates = {
        "accuracy_gate": {"passed": acc_gate, "required": j["min_accuracy_retention_pct"], "actual": results["accuracy_retention_pct"]},
        "latency_gate": {"passed": lat_gate, "required": student["max_latency_ms"], "actual": results["student_latency_ms"]},
        "security_gate": {"passed": sec_gate, "tolerance": j["security_boundary_tolerance"], "actual_deviation": round(1 - results["security_boundary_fidelity"], 4)},
        "resource_gate": {"passed": res_gate, "max_memory_mb": round(teacher["memory_mb"] * 0.5, 1), "actual_memory_mb": results["student_memory_mb"]},
    }
    all_passed = all(g["passed"] for g in gates.values())
    gates["all_passed"] = all_passed
    j["quality_gates"] = gates

    # Auto-advance
    j["state"] = "validated" if all_passed else "rejected"
    j["completed_at"] = _now() if not all_passed else None

    return j

# ── Quality Gates ────────────────────────────────────────────────────
@app.get("/v1/jobs/{jid}/quality-gates")
def quality_gates(jid: str):
    if jid not in jobs:
        raise HTTPException(404, "Job not found")
    j = jobs[jid]
    if not j["quality_gates"]:
        raise HTTPException(400, "Job has not been run yet")
    return {"job_id": jid, "state": j["state"], "quality_gates": j["quality_gates"]}

# ── Comparison ───────────────────────────────────────────────────────
@app.get("/v1/jobs/{jid}/comparison")
def comparison(jid: str):
    if jid not in jobs:
        raise HTTPException(404, "Job not found")
    j = jobs[jid]
    if not j["results"]:
        raise HTTPException(400, "Job has not been run yet")
    teacher = teachers.get(j["teacher_id"], {})
    student = students.get(j["student_id"], {})
    r = j["results"]
    return {
        "job_id": jid,
        "method": j["method"],
        "teacher": {"name": teacher.get("name"), "type": teacher.get("teacher_type"), "parameters": teacher.get("parameter_count"), "accuracy": teacher.get("accuracy_baseline"), "latency_ms": teacher.get("latency_ms"), "memory_mb": teacher.get("memory_mb")},
        "student": {"name": student.get("name"), "platform": student.get("target_platform"), "max_parameters": student.get("max_parameters"), "achieved_accuracy": r["student_accuracy"], "achieved_latency_ms": r["student_latency_ms"], "achieved_memory_mb": r["student_memory_mb"]},
        "compression": {"parameter_reduction": f"{r['parameter_reduction_ratio'] * 100:.1f}%", "latency_speedup": f"{r['latency_speedup']:.1f}x", "memory_reduction": f"{r['memory_reduction_pct']:.1f}%", "accuracy_retained": f"{r['accuracy_retention_pct']:.1f}%"},
        "security": {"boundary_fidelity": r["security_boundary_fidelity"], "boundary_violations": r["boundary_violations"]},
    }

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    jl = list(jobs.values())
    completed = [j for j in jl if j["results"]]
    by_method = {}
    for j in jl:
        by_method[j["method"]] = by_method.get(j["method"], 0) + 1
    by_state = {}
    for j in jl:
        by_state[j["state"]] = by_state.get(j["state"], 0) + 1

    avg_retention = 0
    avg_speedup = 0
    avg_fidelity = 0
    if completed:
        avg_retention = round(sum(j["results"]["accuracy_retention_pct"] for j in completed) / len(completed), 2)
        avg_speedup = round(sum(j["results"]["latency_speedup"] for j in completed) / len(completed), 2)
        avg_fidelity = round(sum(j["results"]["security_boundary_fidelity"] for j in completed) / len(completed), 4)

    validated = sum(1 for j in jl if j["state"] in ("validated", "deployed"))
    rejected = sum(1 for j in jl if j["state"] == "rejected")

    return {
        "total_teachers": len(teachers),
        "total_students": len(students),
        "total_jobs": len(jl),
        "by_method": by_method,
        "by_state": by_state,
        "completed_distillations": len(completed),
        "validated": validated,
        "rejected": rejected,
        "validation_rate": round(validated / max(validated + rejected, 1), 3),
        "avg_accuracy_retention_pct": avg_retention,
        "avg_latency_speedup": avg_speedup,
        "avg_security_boundary_fidelity": avg_fidelity,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9924)
