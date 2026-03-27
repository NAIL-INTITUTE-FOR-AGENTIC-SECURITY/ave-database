"""
Shared Defence Playbook Library — Phase 24 Service 4 of 5
Port: 9803

Community-curated playbook repository with version control,
effectiveness ratings, organisation-specific customisation, and
step-by-step execution tracking.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PlaybookCategory(str, Enum):
    incident_response = "incident_response"
    threat_hunting = "threat_hunting"
    vulnerability_management = "vulnerability_management"
    compliance_audit = "compliance_audit"
    data_protection = "data_protection"
    access_review = "access_review"
    forensic_analysis = "forensic_analysis"
    recovery = "recovery"


class PlaybookState(str, Enum):
    draft = "draft"
    review = "review"
    approved = "approved"
    published = "published"
    deprecated = "deprecated"
    archived = "archived"


PLAYBOOK_STATES = list(PlaybookState)


class StepType(str, Enum):
    manual = "manual"
    automated = "automated"
    decision = "decision"
    notification = "notification"
    escalation = "escalation"


class ExecutionState(str, Enum):
    in_progress = "in_progress"
    completed = "completed"
    aborted = "aborted"
    failed = "failed"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class PlaybookCreate(BaseModel):
    title: str
    description: str = ""
    category: PlaybookCategory
    target_ave_categories: List[str] = Field(default_factory=list)
    estimated_duration_minutes: int = Field(default=60, ge=1)
    required_roles: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    author: str = ""
    organisation: str = ""


class PlaybookRecord(PlaybookCreate):
    playbook_id: str
    state: PlaybookState = PlaybookState.draft
    version: str = "1.0.0"
    version_history: List[Dict[str, Any]] = Field(default_factory=list)
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    reviews: List[Dict[str, Any]] = Field(default_factory=list)
    avg_rating: float = 0.0
    fork_of: Optional[str] = None
    forked_by_org: Optional[str] = None
    execution_count: int = 0
    created_at: str
    updated_at: str


class StepCreate(BaseModel):
    title: str
    step_type: StepType = StepType.manual
    instructions: str = ""
    expected_duration_minutes: int = Field(default=10, ge=1)
    required_role: str = ""
    success_criteria: str = ""


class ReviewCreate(BaseModel):
    reviewer: str
    organisation: str = ""
    rating: int = Field(ge=1, le=5)
    comment: str = ""
    security_concern: bool = False


class ForkRequest(BaseModel):
    organisation: str
    custom_title: str = ""


class ExecutionStart(BaseModel):
    executor: str
    organisation: str = ""
    context: str = ""


class ExecutionRecord(BaseModel):
    execution_id: str
    playbook_id: str
    executor: str
    organisation: str
    context: str
    state: ExecutionState = ExecutionState.in_progress
    step_results: List[Dict[str, Any]] = Field(default_factory=list)
    started_at: str
    completed_at: Optional[str] = None


class StepComplete(BaseModel):
    outcome: str = "success"
    actual_duration_minutes: int = 0
    notes: str = ""


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

playbooks: Dict[str, PlaybookRecord] = {}
executions: Dict[str, ExecutionRecord] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Shared Defence Playbook Library",
    description="Phase 24 — Community-curated playbooks with versioning, ratings, forking, and execution tracking",
    version="24.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    published = sum(1 for p in playbooks.values() if p.state == PlaybookState.published)
    return {
        "service": "shared-defence-playbook-library",
        "status": "healthy",
        "phase": 24,
        "port": 9803,
        "stats": {
            "playbooks": len(playbooks),
            "published": published,
            "executions": len(executions),
        },
        "timestamp": _now(),
    }


# -- Playbooks ---------------------------------------------------------------

@app.post("/v1/playbooks", status_code=201)
def create_playbook(body: PlaybookCreate):
    pid = f"PB-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = PlaybookRecord(**body.dict(), playbook_id=pid, created_at=now, updated_at=now)
    record.version_history.append({"version": "1.0.0", "changed_at": now, "author": body.author})
    playbooks[pid] = record
    return record.dict()


@app.get("/v1/playbooks")
def list_playbooks(
    category: Optional[PlaybookCategory] = None,
    state: Optional[PlaybookState] = None,
    tag: Optional[str] = None,
    min_rating: Optional[float] = None,
    search: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
):
    results = list(playbooks.values())
    if category:
        results = [p for p in results if p.category == category]
    if state:
        results = [p for p in results if p.state == state]
    if tag:
        results = [p for p in results if tag in p.tags]
    if min_rating is not None:
        results = [p for p in results if p.avg_rating >= min_rating]
    if search:
        q = search.lower()
        results = [p for p in results if q in p.title.lower() or q in p.description.lower()]
    results.sort(key=lambda p: p.avg_rating, reverse=True)
    return {"playbooks": [p.dict() for p in results[:limit]], "total": len(results)}


@app.get("/v1/playbooks/{pb_id}")
def get_playbook(pb_id: str):
    if pb_id not in playbooks:
        raise HTTPException(404, "Playbook not found")
    return playbooks[pb_id].dict()


@app.patch("/v1/playbooks/{pb_id}/advance")
def advance_playbook(pb_id: str):
    if pb_id not in playbooks:
        raise HTTPException(404, "Playbook not found")
    pb = playbooks[pb_id]
    idx = PLAYBOOK_STATES.index(pb.state)
    if idx >= len(PLAYBOOK_STATES) - 1:
        raise HTTPException(409, "Playbook already at final state")
    pb.state = PLAYBOOK_STATES[idx + 1]
    pb.updated_at = _now()
    return {"playbook_id": pb_id, "state": pb.state.value}


# -- Steps -------------------------------------------------------------------

@app.post("/v1/playbooks/{pb_id}/steps", status_code=201)
def add_step(pb_id: str, body: StepCreate):
    if pb_id not in playbooks:
        raise HTTPException(404, "Playbook not found")
    pb = playbooks[pb_id]
    step = {
        "step_id": f"STP-{uuid.uuid4().hex[:8]}",
        "step_number": len(pb.steps) + 1,
        **body.dict(),
        "added_at": _now(),
    }
    pb.steps.append(step)
    pb.updated_at = _now()
    return step


@app.get("/v1/playbooks/{pb_id}/steps")
def list_steps(pb_id: str):
    if pb_id not in playbooks:
        raise HTTPException(404, "Playbook not found")
    return {"steps": playbooks[pb_id].steps, "total": len(playbooks[pb_id].steps)}


# -- Reviews -----------------------------------------------------------------

@app.post("/v1/playbooks/{pb_id}/reviews", status_code=201)
def submit_review(pb_id: str, body: ReviewCreate):
    if pb_id not in playbooks:
        raise HTTPException(404, "Playbook not found")
    pb = playbooks[pb_id]
    review = {
        "review_id": f"RV-{uuid.uuid4().hex[:8]}",
        **body.dict(),
        "submitted_at": _now(),
    }
    pb.reviews.append(review)
    # Recalculate avg
    ratings = [r["rating"] for r in pb.reviews]
    pb.avg_rating = round(sum(ratings) / len(ratings), 2) if ratings else 0.0
    pb.updated_at = _now()
    return review


@app.get("/v1/playbooks/{pb_id}/reviews")
def list_reviews(pb_id: str):
    if pb_id not in playbooks:
        raise HTTPException(404, "Playbook not found")
    return {"reviews": playbooks[pb_id].reviews, "avg_rating": playbooks[pb_id].avg_rating}


# -- Forking -----------------------------------------------------------------

@app.post("/v1/playbooks/{pb_id}/fork", status_code=201)
def fork_playbook(pb_id: str, body: ForkRequest):
    if pb_id not in playbooks:
        raise HTTPException(404, "Playbook not found")
    original = playbooks[pb_id]
    fid = f"PB-{uuid.uuid4().hex[:12]}"
    now = _now()
    forked = PlaybookRecord(
        playbook_id=fid,
        title=body.custom_title or f"{original.title} (fork: {body.organisation})",
        description=original.description,
        category=original.category,
        target_ave_categories=original.target_ave_categories[:],
        estimated_duration_minutes=original.estimated_duration_minutes,
        required_roles=original.required_roles[:],
        tags=original.tags[:] + ["forked"],
        author=body.organisation,
        organisation=body.organisation,
        state=PlaybookState.draft,
        steps=[s.copy() for s in original.steps],
        fork_of=pb_id,
        forked_by_org=body.organisation,
        created_at=now,
        updated_at=now,
    )
    forked.version_history.append({"version": "1.0.0", "changed_at": now, "author": body.organisation, "forked_from": pb_id})
    playbooks[fid] = forked
    return forked.dict()


# -- Execution ---------------------------------------------------------------

@app.post("/v1/playbooks/{pb_id}/execute", status_code=201)
def start_execution(pb_id: str, body: ExecutionStart):
    if pb_id not in playbooks:
        raise HTTPException(404, "Playbook not found")
    pb = playbooks[pb_id]
    eid = f"EXEC-{uuid.uuid4().hex[:12]}"
    record = ExecutionRecord(
        execution_id=eid, playbook_id=pb_id,
        executor=body.executor, organisation=body.organisation,
        context=body.context, started_at=_now(),
    )
    executions[eid] = record
    pb.execution_count += 1
    return record.dict()


@app.post("/v1/executions/{exec_id}/steps/{step_number}/complete")
def complete_step(exec_id: str, step_number: int, body: StepComplete):
    if exec_id not in executions:
        raise HTTPException(404, "Execution not found")
    execution = executions[exec_id]
    pb = playbooks.get(execution.playbook_id)
    if not pb:
        raise HTTPException(404, "Playbook not found")

    step_info = next((s for s in pb.steps if s["step_number"] == step_number), None)
    if not step_info:
        raise HTTPException(404, f"Step {step_number} not found")

    execution.step_results.append({
        "step_number": step_number,
        "step_title": step_info["title"],
        "outcome": body.outcome,
        "actual_duration_minutes": body.actual_duration_minutes,
        "notes": body.notes,
        "completed_at": _now(),
    })

    # Auto-complete execution if all steps done
    if len(execution.step_results) >= len(pb.steps):
        failed = any(r["outcome"] == "failed" for r in execution.step_results)
        execution.state = ExecutionState.failed if failed else ExecutionState.completed
        execution.completed_at = _now()

    return {"execution_id": exec_id, "step": step_number, "state": execution.state.value}


@app.get("/v1/executions")
def list_executions(
    playbook_id: Optional[str] = None,
    state: Optional[ExecutionState] = None,
    limit: int = Query(default=50, ge=1, le=500),
):
    results = list(executions.values())
    if playbook_id:
        results = [e for e in results if e.playbook_id == playbook_id]
    if state:
        results = [e for e in results if e.state == state]
    results.sort(key=lambda e: e.started_at, reverse=True)
    return {"executions": [e.dict() for e in results[:limit]], "total": len(results)}


# -- Analytics ----------------------------------------------------------------

@app.get("/v1/analytics")
def analytics():
    cat_dist: Dict[str, int] = defaultdict(int)
    state_dist: Dict[str, int] = defaultdict(int)
    org_dist: Dict[str, int] = defaultdict(int)
    for pb in playbooks.values():
        cat_dist[pb.category.value] += 1
        state_dist[pb.state.value] += 1
        if pb.organisation:
            org_dist[pb.organisation] += 1

    ratings = [pb.avg_rating for pb in playbooks.values() if pb.avg_rating > 0]
    exec_states: Dict[str, int] = defaultdict(int)
    for ex in executions.values():
        exec_states[ex.state.value] += 1

    total_est = sum(pb.estimated_duration_minutes for pb in playbooks.values())
    total_actual = sum(
        r.get("actual_duration_minutes", 0)
        for ex in executions.values()
        for r in ex.step_results
    )

    return {
        "playbooks": {
            "total": len(playbooks),
            "category_distribution": dict(cat_dist),
            "state_distribution": dict(state_dist),
            "organisation_distribution": dict(org_dist),
            "forked": sum(1 for p in playbooks.values() if p.fork_of),
            "avg_rating": round(sum(ratings) / len(ratings), 2) if ratings else None,
            "total_reviews": sum(len(p.reviews) for p in playbooks.values()),
        },
        "executions": {
            "total": len(executions),
            "state_distribution": dict(exec_states),
            "total_estimated_minutes": total_est,
            "total_actual_minutes": total_actual,
        },
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9803)
