"""
AI Ethics Tribunal — Phase 21 Service 3 of 5
Port: 9502

Multi-stakeholder ethical review board with case submission,
structured deliberation, precedent tracking, binding resolution
enforcement, and conflict-of-interest management.
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

class PanellistRole(str, Enum):
    chief_justice = "chief_justice"
    justice = "justice"
    advocate = "advocate"
    technical_expert = "technical_expert"
    public_representative = "public_representative"


class CaseCategory(str, Enum):
    bias_discrimination = "bias_discrimination"
    privacy_violation = "privacy_violation"
    autonomy_override = "autonomy_override"
    safety_harm = "safety_harm"
    transparency_failure = "transparency_failure"
    accountability_gap = "accountability_gap"
    consent_violation = "consent_violation"
    environmental_impact = "environmental_impact"


class CaseStage(str, Enum):
    filed = "filed"
    screening = "screening"
    panel_assigned = "panel_assigned"
    deliberation = "deliberation"
    voting = "voting"
    resolution = "resolution"
    enforcement = "enforcement"


STAGE_ORDER = list(CaseStage)


class CaseSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class VotingMethod(str, Enum):
    simple_majority = "simple_majority"
    supermajority = "supermajority"
    unanimous = "unanimous"


class ArgumentType(str, Enum):
    supporting = "supporting"
    opposing = "opposing"
    amicus = "amicus"


class ResolutionType(str, Enum):
    binding = "binding"
    advisory = "advisory"


class EnforcementStatus(str, Enum):
    pending = "pending"
    in_progress = "in_progress"
    compliant = "compliant"
    non_compliant = "non_compliant"
    escalated = "escalated"


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

class PanellistCreate(BaseModel):
    name: str
    role: PanellistRole
    expertise_domains: List[str] = Field(default_factory=list)
    organisation: str = ""
    term_start: str = ""
    term_end: str = ""
    recusals: List[str] = Field(default_factory=list)
    conflicts_of_interest: List[str] = Field(default_factory=list)


class PanellistRecord(PanellistCreate):
    panellist_id: str
    cases_served: int = 0
    votes_cast: int = 0
    created_at: str


class CaseCreate(BaseModel):
    title: str
    category: CaseCategory
    severity: CaseSeverity = CaseSeverity.medium
    description: str = ""
    complainant: str = ""
    respondent: str = ""
    ave_categories: List[str] = Field(default_factory=list)
    evidence_summary: str = ""
    voting_method: VotingMethod = VotingMethod.simple_majority
    quorum_percent: float = Field(default=60.0, ge=0, le=100)


class CaseRecord(CaseCreate):
    case_id: str
    stage: CaseStage = CaseStage.filed
    assigned_panel: List[str] = Field(default_factory=list)
    arguments: List[Dict[str, Any]] = Field(default_factory=list)
    votes: Dict[str, str] = Field(default_factory=dict)  # panellist_id -> "uphold"/"dismiss"/"partial"
    resolution: Optional[Dict[str, Any]] = None
    enforcement_status: EnforcementStatus = EnforcementStatus.pending
    precedent_refs: List[str] = Field(default_factory=list)
    created_at: str
    updated_at: str


class ArgumentSubmit(BaseModel):
    panellist_id: str
    argument_type: ArgumentType
    content: str
    evidence_refs: List[str] = Field(default_factory=list)


class VoteSubmit(BaseModel):
    panellist_id: str
    decision: str  # "uphold" | "dismiss" | "partial"
    reasoning: str = ""
    dissenting_opinion: str = ""


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

panellists: Dict[str, PanellistRecord] = {}
cases: Dict[str, CaseRecord] = {}
precedents: List[Dict[str, Any]] = []


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI Ethics Tribunal",
    description="Phase 21 — Multi-stakeholder ethical review board with deliberation, voting, precedents, enforcement",
    version="21.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {
        "service": "ai-ethics-tribunal",
        "status": "healthy",
        "phase": 21,
        "port": 9502,
        "stats": {
            "panellists": len(panellists),
            "cases": len(cases),
            "precedents": len(precedents),
        },
        "timestamp": _now(),
    }


# ── Panellists ─────────────────────────────────────────────────────────────

@app.post("/v1/panellists", status_code=201)
def register_panellist(body: PanellistCreate):
    pid = f"PNL-{uuid.uuid4().hex[:12]}"
    record = PanellistRecord(**body.dict(), panellist_id=pid, created_at=_now())
    panellists[pid] = record
    return record.dict()


@app.get("/v1/panellists")
def list_panellists(role: Optional[PanellistRole] = None):
    results = list(panellists.values())
    if role:
        results = [p for p in results if p.role == role]
    return {"panellists": [p.dict() for p in results], "total": len(results)}


# ── Cases ──────────────────────────────────────────────────────────────────

@app.post("/v1/cases", status_code=201)
def file_case(body: CaseCreate):
    cid = f"CASE-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = CaseRecord(**body.dict(), case_id=cid, created_at=now, updated_at=now)

    # Auto-assign panel from available panellists (up to 5)
    eligible = [p for p in panellists.values() if cid not in p.recusals]
    # Prefer justices and chief_justice
    eligible.sort(key=lambda p: (0 if p.role in (PanellistRole.chief_justice, PanellistRole.justice) else 1, p.cases_served))
    panel = eligible[:5]
    record.assigned_panel = [p.panellist_id for p in panel]
    for p in panel:
        p.cases_served += 1
    if panel:
        record.stage = CaseStage.panel_assigned

    cases[cid] = record
    return record.dict()


@app.get("/v1/cases")
def list_cases(
    stage: Optional[CaseStage] = None,
    category: Optional[CaseCategory] = None,
    severity: Optional[CaseSeverity] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(cases.values())
    if stage:
        results = [c for c in results if c.stage == stage]
    if category:
        results = [c for c in results if c.category == category]
    if severity:
        results = [c for c in results if c.severity == severity]
    results.sort(key=lambda c: c.created_at, reverse=True)
    return {"cases": [c.dict() for c in results[:limit]], "total": len(results)}


@app.get("/v1/cases/{case_id}")
def get_case(case_id: str):
    if case_id not in cases:
        raise HTTPException(404, "Case not found")
    return cases[case_id].dict()


# ── Arguments ──────────────────────────────────────────────────────────────

@app.post("/v1/cases/{case_id}/arguments", status_code=201)
def submit_argument(case_id: str, body: ArgumentSubmit):
    if case_id not in cases:
        raise HTTPException(404, "Case not found")
    c = cases[case_id]
    if body.panellist_id not in c.assigned_panel:
        raise HTTPException(403, "Panellist not on assigned panel")
    if c.stage.value not in ("panel_assigned", "deliberation"):
        raise HTTPException(409, f"Cannot submit arguments in stage {c.stage.value}")

    arg = {
        "argument_id": f"ARG-{uuid.uuid4().hex[:8]}",
        "panellist_id": body.panellist_id,
        "argument_type": body.argument_type.value,
        "content": body.content,
        "evidence_refs": body.evidence_refs,
        "submitted_at": _now(),
    }
    c.arguments.append(arg)
    c.stage = CaseStage.deliberation
    c.updated_at = _now()
    return arg


# ── Voting ─────────────────────────────────────────────────────────────────

@app.post("/v1/cases/{case_id}/vote", status_code=201)
def cast_vote(case_id: str, body: VoteSubmit):
    if case_id not in cases:
        raise HTTPException(404, "Case not found")
    c = cases[case_id]
    if body.panellist_id not in c.assigned_panel:
        raise HTTPException(403, "Panellist not on assigned panel")
    if body.panellist_id in c.votes:
        raise HTTPException(409, "Panellist has already voted")

    # Must have at least 1 argument before voting
    if not c.arguments:
        raise HTTPException(422, "No arguments submitted — deliberation required before voting")

    c.votes[body.panellist_id] = body.decision
    if body.panellist_id in panellists:
        panellists[body.panellist_id].votes_cast += 1
    c.stage = CaseStage.voting
    c.updated_at = _now()

    # Check if quorum reached
    quorum_needed = max(1, int(len(c.assigned_panel) * c.quorum_percent / 100))
    if len(c.votes) >= quorum_needed:
        _resolve_case(c)

    return {
        "case_id": case_id,
        "votes_cast": len(c.votes),
        "quorum_needed": quorum_needed,
        "stage": c.stage.value,
    }


def _resolve_case(c: CaseRecord):
    """Tally votes and produce resolution."""
    tally: Dict[str, int] = defaultdict(int)
    for decision in c.votes.values():
        tally[decision] += 1

    total_votes = len(c.votes)
    panel_size = len(c.assigned_panel)
    uphold = tally.get("uphold", 0)
    dismiss = tally.get("dismiss", 0)

    if c.voting_method == VotingMethod.simple_majority:
        outcome = "upheld" if uphold > total_votes / 2 else "dismissed"
    elif c.voting_method == VotingMethod.supermajority:
        outcome = "upheld" if uphold >= total_votes * 2 / 3 else "dismissed"
    elif c.voting_method == VotingMethod.unanimous:
        outcome = "upheld" if uphold == total_votes else "dismissed"
    else:
        outcome = "upheld" if uphold > dismiss else "dismissed"

    dissents = [pid for pid, d in c.votes.items() if d != ("uphold" if outcome == "upheld" else "dismiss")]

    c.resolution = {
        "outcome": outcome,
        "resolution_type": "binding",
        "tally": dict(tally),
        "total_votes": total_votes,
        "panel_size": panel_size,
        "dissenting_panellists": dissents,
        "resolved_at": _now(),
    }
    c.stage = CaseStage.resolution
    c.updated_at = _now()

    # Auto-create precedent
    precedent = {
        "precedent_id": f"PREC-{uuid.uuid4().hex[:8]}",
        "case_id": c.case_id,
        "category": c.category.value,
        "severity": c.severity.value,
        "outcome": outcome,
        "principle": f"Case {c.case_id}: {c.title} — {outcome}",
        "ave_categories": c.ave_categories,
        "created_at": _now(),
    }
    precedents.append(precedent)
    c.precedent_refs.append(precedent["precedent_id"])


@app.get("/v1/cases/{case_id}/resolution")
def get_resolution(case_id: str):
    if case_id not in cases:
        raise HTTPException(404, "Case not found")
    c = cases[case_id]
    if not c.resolution:
        raise HTTPException(404, "Case not yet resolved")
    return {**c.resolution, "case_id": case_id, "category": c.category.value, "title": c.title}


# ── Enforcement ────────────────────────────────────────────────────────────

@app.post("/v1/cases/{case_id}/enforce")
def initiate_enforcement(case_id: str):
    if case_id not in cases:
        raise HTTPException(404, "Case not found")
    c = cases[case_id]
    if not c.resolution:
        raise HTTPException(422, "Case not yet resolved")
    if c.resolution.get("resolution_type") != "binding":
        raise HTTPException(409, "Only binding resolutions can be enforced")
    c.enforcement_status = EnforcementStatus.in_progress
    c.stage = CaseStage.enforcement
    c.updated_at = _now()
    return {"case_id": case_id, "enforcement_status": c.enforcement_status.value}


# ── Precedents ─────────────────────────────────────────────────────────────

@app.get("/v1/precedents")
def search_precedents(
    category: Optional[CaseCategory] = None,
    keyword: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
):
    results = precedents[:]
    if category:
        results = [p for p in results if p["category"] == category.value]
    if keyword:
        kw = keyword.lower()
        results = [p for p in results if kw in p.get("principle", "").lower()]
    return {"precedents": results[:limit], "total": len(results)}


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/v1/analytics")
def analytics():
    stage_dist: Dict[str, int] = defaultdict(int)
    cat_dist: Dict[str, int] = defaultdict(int)
    sev_dist: Dict[str, int] = defaultdict(int)
    outcome_dist: Dict[str, int] = defaultdict(int)
    for c in cases.values():
        stage_dist[c.stage.value] += 1
        cat_dist[c.category.value] += 1
        sev_dist[c.severity.value] += 1
        if c.resolution:
            outcome_dist[c.resolution.get("outcome", "unknown")] += 1
    return {
        "panellists": len(panellists),
        "cases": {
            "total": len(cases),
            "stage_distribution": dict(stage_dist),
            "category_distribution": dict(cat_dist),
            "severity_distribution": dict(sev_dist),
        },
        "outcomes": dict(outcome_dist),
        "precedents": len(precedents),
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9502)
