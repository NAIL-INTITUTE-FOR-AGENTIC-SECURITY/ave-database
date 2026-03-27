"""
Meta-Governance Council — Phase 19 Service 5 of 5
Port: 9304

Constitutional framework with articles and hierarchy, council
membership with roles and terms, 7-stage amendment pipeline,
voting with multiple protocols, power-balance engine, and
governance health dashboard.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ArticleCategory(str, Enum):
    human_oversight = "human_oversight"
    safety_invariants = "safety_invariants"
    transparency_requirements = "transparency_requirements"
    power_distribution = "power_distribution"
    amendment_procedures = "amendment_procedures"


class ArticleTier(str, Enum):
    constitutional = "constitutional"
    statutory = "statutory"
    procedural = "procedural"


class CouncilRole(str, Enum):
    chair = "chair"
    voting_member = "voting_member"
    observer = "observer"
    technical_advisor = "technical_advisor"
    ombudsman = "ombudsman"


class AmendmentStage(str, Enum):
    proposal = "proposal"
    discussion = "discussion"
    committee_review = "committee_review"
    public_comment = "public_comment"
    vote = "vote"
    ratification = "ratification"
    enacted = "enacted"


class AmendmentType(str, Enum):
    add = "add"
    modify = "modify"
    repeal = "repeal"
    meta = "meta"


class VotingMethod(str, Enum):
    simple_majority = "simple_majority"
    supermajority = "supermajority"
    unanimous = "unanimous"
    ranked_choice = "ranked_choice"


class PowerDomain(str, Enum):
    legislative = "legislative"
    executive = "executive"
    judicial = "judicial"
    oversight = "oversight"


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

class ArticleCreate(BaseModel):
    title: str
    body: str
    category: ArticleCategory
    tier: ArticleTier = ArticleTier.statutory
    cross_references: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ArticleRecord(ArticleCreate):
    article_id: str
    version: int = 1
    enacted_at: str
    updated_at: str


class MemberCreate(BaseModel):
    name: str
    role: CouncilRole
    expertise_domains: List[str] = Field(default_factory=list)
    term_start: Optional[str] = None
    term_end: Optional[str] = None
    is_human: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MemberRecord(MemberCreate):
    member_id: str
    active: bool = True
    votes_cast: int = 0
    recusals: int = 0
    created_at: str


class AmendmentCreate(BaseModel):
    title: str
    description: str
    amendment_type: AmendmentType
    target_article_id: Optional[str] = None
    proposed_text: str = ""
    sponsor_ids: List[str] = Field(default_factory=list, description="Minimum 2 sponsors")
    category: Optional[ArticleCategory] = None


class AmendmentRecord(AmendmentCreate):
    amendment_id: str
    stage: AmendmentStage = AmendmentStage.proposal
    deliberation_days: int = 14
    votes: Dict[str, str] = Field(default_factory=dict)  # member_id -> "for"|"against"|"abstain"
    committee_notes: List[str] = Field(default_factory=list)
    public_comments: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str
    updated_at: str


class VoteSubmission(BaseModel):
    amendment_id: str
    member_id: str
    vote: str  # "for" | "against" | "abstain"
    reasoning: str = ""


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

articles: Dict[str, ArticleRecord] = {}
members: Dict[str, MemberRecord] = {}
amendments: Dict[str, AmendmentRecord] = {}
power_log: List[Dict[str, Any]] = []
governance_snapshots: List[Dict[str, Any]] = []


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Bootstrap Constitutional Articles
# ---------------------------------------------------------------------------

_BOOTSTRAP_ARTICLES = [
    {
        "title": "Human Oversight Supremacy",
        "body": "All autonomous decisions affecting safety-critical operations must be reviewable and overridable by authorised human operators within a reasonable time frame.",
        "category": ArticleCategory.human_oversight,
        "tier": ArticleTier.constitutional,
    },
    {
        "title": "Safety Invariant Preservation",
        "body": "No governance action, policy change, or system modification shall weaken or circumvent established safety invariants without supermajority approval and mandatory cooling-off period.",
        "category": ArticleCategory.safety_invariants,
        "tier": ArticleTier.constitutional,
    },
    {
        "title": "Transparency Mandate",
        "body": "All governance decisions, voting records, amendment histories, and power distribution metrics must be publicly accessible and auditable.",
        "category": ArticleCategory.transparency_requirements,
        "tier": ArticleTier.constitutional,
    },
    {
        "title": "Power Concentration Limit",
        "body": "No single entity—human or AI—shall hold more than 30% of decision-making authority across any governance domain. Automatic re-balancing shall trigger upon threshold breach.",
        "category": ArticleCategory.power_distribution,
        "tier": ArticleTier.constitutional,
    },
    {
        "title": "Amendment Safeguard",
        "body": "Constitutional articles require supermajority vote, minimum 14-day deliberation, committee review, and public comment period. Meta-amendments (changes to amendment procedures) require unanimous consent.",
        "category": ArticleCategory.amendment_procedures,
        "tier": ArticleTier.constitutional,
    },
]


def _bootstrap():
    if articles:
        return
    now = _now()
    for i, a in enumerate(_BOOTSTRAP_ARTICLES):
        aid = f"ART-{str(i + 1).zfill(4)}"
        articles[aid] = ArticleRecord(
            **a,
            article_id=aid,
            enacted_at=now,
            updated_at=now,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

STAGE_ORDER = list(AmendmentStage)


def _next_stage(current: AmendmentStage) -> Optional[AmendmentStage]:
    idx = STAGE_ORDER.index(current)
    if idx + 1 < len(STAGE_ORDER):
        return STAGE_ORDER[idx + 1]
    return None


def _voting_method_for(amendment: AmendmentRecord) -> VotingMethod:
    if amendment.amendment_type == AmendmentType.meta:
        return VotingMethod.unanimous
    target = articles.get(amendment.target_article_id) if amendment.target_article_id else None
    if target and target.tier == ArticleTier.constitutional:
        return VotingMethod.supermajority
    return VotingMethod.simple_majority


def _tally_votes(amendment: AmendmentRecord) -> Dict[str, Any]:
    eligible = [m for m in members.values() if m.active and m.role in (CouncilRole.chair, CouncilRole.voting_member)]
    total_eligible = len(eligible)
    eligible_ids = {m.member_id for m in eligible}
    valid = {k: v for k, v in amendment.votes.items() if k in eligible_ids}
    breakdown = {"for": 0, "against": 0, "abstain": 0}
    for v in valid.values():
        if v in breakdown:
            breakdown[v] += 1
    votes_cast = breakdown["for"] + breakdown["against"] + breakdown["abstain"]
    quorum_met = votes_cast / max(total_eligible, 1) >= 0.6
    method = _voting_method_for(amendment)
    if not quorum_met:
        result = "no_quorum"
    elif method == VotingMethod.simple_majority:
        result = "passed" if breakdown["for"] > breakdown["against"] else "failed"
    elif method == VotingMethod.supermajority:
        result = "passed" if breakdown["for"] >= (votes_cast * 2 / 3) else "failed"
    elif method == VotingMethod.unanimous:
        result = "passed" if breakdown["against"] == 0 and breakdown["for"] > 0 else "failed"
    else:
        result = "passed" if breakdown["for"] > breakdown["against"] else "failed"
    return {
        "method": method.value,
        "total_eligible": total_eligible,
        "votes_cast": votes_cast,
        "quorum_met": quorum_met,
        "breakdown": breakdown,
        "result": result,
    }


def _power_balance() -> Dict[str, Any]:
    """Compute power distribution across domains."""
    domain_holders: Dict[str, Dict[str, float]] = {d.value: {} for d in PowerDomain}
    for m in members.values():
        if not m.active:
            continue
        weight = 1.0
        if m.role == CouncilRole.chair:
            weight = 2.0
            domains = [PowerDomain.legislative, PowerDomain.executive, PowerDomain.oversight]
        elif m.role == CouncilRole.voting_member:
            weight = 1.0
            domains = [PowerDomain.legislative]
        elif m.role == CouncilRole.ombudsman:
            weight = 1.5
            domains = [PowerDomain.judicial, PowerDomain.oversight]
        elif m.role == CouncilRole.technical_advisor:
            weight = 0.5
            domains = [PowerDomain.executive]
        else:
            domains = []
            weight = 0.0
        entity_key = f"{'human' if m.is_human else 'ai'}:{m.member_id}"
        for d in domains:
            domain_holders[d.value][entity_key] = domain_holders[d.value].get(entity_key, 0) + weight

    concentration_alerts = []
    for domain, holders in domain_holders.items():
        total = sum(holders.values()) or 1.0
        for entity, w in holders.items():
            share = w / total
            if share > 0.30:
                concentration_alerts.append({
                    "domain": domain,
                    "entity": entity,
                    "share": round(share, 4),
                    "threshold": 0.30,
                })
    # Human vs AI balance
    human_weight = sum(
        1.0 for m in members.values() if m.active and m.is_human and m.role in (CouncilRole.chair, CouncilRole.voting_member)
    )
    ai_weight = sum(
        1.0 for m in members.values() if m.active and not m.is_human and m.role in (CouncilRole.chair, CouncilRole.voting_member)
    )
    total_weight = human_weight + ai_weight or 1.0
    return {
        "domains": {
            d: {
                "holders": holders,
                "total_weight": round(sum(holders.values()), 2),
            }
            for d, holders in domain_holders.items()
        },
        "concentration_alerts": concentration_alerts,
        "human_ai_balance": {
            "human_share": round(human_weight / total_weight, 4),
            "ai_share": round(ai_weight / total_weight, 4),
        },
    }


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Meta-Governance Council",
    description="Phase 19 — Constitution, council, amendments, voting, power balance, and governance health",
    version="19.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_bootstrap()


@app.get("/health")
def health():
    return {
        "service": "meta-governance-council",
        "status": "healthy",
        "phase": 19,
        "port": 9304,
        "stats": {
            "articles": len(articles),
            "members": len(members),
            "amendments": len(amendments),
        },
        "timestamp": _now(),
    }


# ── Constitution ───────────────────────────────────────────────────────────

@app.get("/v1/constitution")
def get_constitution():
    by_category: Dict[str, List] = defaultdict(list)
    for a in articles.values():
        by_category[a.category.value].append(a.dict())
    return {
        "articles": [a.dict() for a in articles.values()],
        "by_category": dict(by_category),
        "total": len(articles),
    }


@app.get("/v1/constitution/articles/{article_id}")
def get_article(article_id: str):
    if article_id not in articles:
        raise HTTPException(404, "Article not found")
    a = articles[article_id]
    refs = [articles[r].dict() for r in a.cross_references if r in articles]
    return {**a.dict(), "resolved_references": refs}


@app.post("/v1/constitution/validate")
def validate_constitution():
    """Check consistency of cross-references and structural integrity."""
    issues = []
    for a in articles.values():
        for ref in a.cross_references:
            if ref not in articles:
                issues.append({"article_id": a.article_id, "issue": f"Dangling cross-reference: {ref}"})
    # Check category coverage
    covered = {a.category for a in articles.values()}
    for cat in ArticleCategory:
        if cat not in covered:
            issues.append({"issue": f"No article covers category: {cat.value}"})
    return {"valid": len(issues) == 0, "issues": issues}


# ── Members ────────────────────────────────────────────────────────────────

@app.post("/v1/members", status_code=201)
def add_member(body: MemberCreate):
    mid = f"MEM-{uuid.uuid4().hex[:12]}"
    record = MemberRecord(**body.dict(), member_id=mid, created_at=_now())
    if not body.term_start:
        record.term_start = _now()
    members[mid] = record
    return record.dict()


@app.get("/v1/members")
def list_members(role: Optional[CouncilRole] = None, active: Optional[bool] = None):
    results = list(members.values())
    if role:
        results = [m for m in results if m.role == role]
    if active is not None:
        results = [m for m in results if m.active == active]
    return {"members": [m.dict() for m in results], "total": len(results)}


@app.get("/v1/members/{member_id}")
def get_member(member_id: str):
    if member_id not in members:
        raise HTTPException(404, "Member not found")
    return members[member_id].dict()


@app.delete("/v1/members/{member_id}")
def deactivate_member(member_id: str):
    if member_id not in members:
        raise HTTPException(404, "Member not found")
    members[member_id].active = False
    return {"deactivated": member_id}


# ── Amendments ─────────────────────────────────────────────────────────────

@app.post("/v1/amendments", status_code=201)
def create_amendment(body: AmendmentCreate):
    if len(body.sponsor_ids) < 2:
        raise HTTPException(422, "Minimum 2 sponsors required")
    for sid in body.sponsor_ids:
        if sid not in members:
            raise HTTPException(404, f"Sponsor {sid} not found")
    if body.target_article_id and body.target_article_id not in articles:
        raise HTTPException(404, "Target article not found")
    amid = f"AMD-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = AmendmentRecord(**body.dict(), amendment_id=amid, created_at=now, updated_at=now)
    amendments[amid] = record
    return record.dict()


@app.get("/v1/amendments")
def list_amendments(stage: Optional[AmendmentStage] = None):
    results = list(amendments.values())
    if stage:
        results = [a for a in results if a.stage == stage]
    return {"amendments": [a.dict() for a in results], "total": len(results)}


@app.get("/v1/amendments/{amendment_id}")
def get_amendment(amendment_id: str):
    if amendment_id not in amendments:
        raise HTTPException(404, "Amendment not found")
    a = amendments[amendment_id]
    tally = _tally_votes(a) if a.votes else None
    return {**a.dict(), "tally": tally}


@app.post("/v1/amendments/{amendment_id}/advance")
def advance_amendment(amendment_id: str):
    if amendment_id not in amendments:
        raise HTTPException(404, "Amendment not found")
    a = amendments[amendment_id]
    next_s = _next_stage(a.stage)
    if next_s is None:
        raise HTTPException(422, "Amendment already at final stage")
    # Gate checks
    if a.stage == AmendmentStage.vote:
        tally = _tally_votes(a)
        if tally["result"] != "passed":
            raise HTTPException(422, f"Vote did not pass: {tally['result']}")
    a.stage = next_s
    a.updated_at = _now()
    # If enacted, apply to constitution
    if next_s == AmendmentStage.enacted and a.target_article_id:
        target = articles.get(a.target_article_id)
        if target and a.amendment_type == AmendmentType.modify:
            target.body = a.proposed_text
            target.version += 1
            target.updated_at = _now()
        elif a.amendment_type == AmendmentType.repeal and a.target_article_id in articles:
            del articles[a.target_article_id]
        elif a.amendment_type == AmendmentType.add:
            new_aid = f"ART-{uuid.uuid4().hex[:8]}"
            articles[new_aid] = ArticleRecord(
                title=a.title,
                body=a.proposed_text,
                category=a.category or ArticleCategory.human_oversight,
                tier=ArticleTier.statutory,
                article_id=new_aid,
                enacted_at=_now(),
                updated_at=_now(),
            )
    return {"amendment_id": amendment_id, "new_stage": next_s.value}


@app.post("/v1/amendments/{amendment_id}/vote")
def submit_vote(amendment_id: str, body: VoteSubmission):
    if amendment_id not in amendments:
        raise HTTPException(404, "Amendment not found")
    a = amendments[amendment_id]
    if a.stage != AmendmentStage.vote:
        raise HTTPException(422, "Amendment not in voting stage")
    if body.member_id not in members:
        raise HTTPException(404, "Member not found")
    m = members[body.member_id]
    if not m.active:
        raise HTTPException(422, "Member is inactive")
    if m.role not in (CouncilRole.chair, CouncilRole.voting_member):
        raise HTTPException(422, "Member does not have voting rights")
    if body.vote not in ("for", "against", "abstain"):
        raise HTTPException(422, "Vote must be 'for', 'against', or 'abstain'")
    a.votes[body.member_id] = body.vote
    a.updated_at = _now()
    m.votes_cast += 1
    return {"recorded": True, "amendment_id": amendment_id, "member_id": body.member_id, "vote": body.vote}


@app.get("/v1/amendments/{amendment_id}/results")
def vote_results(amendment_id: str):
    if amendment_id not in amendments:
        raise HTTPException(404, "Amendment not found")
    return _tally_votes(amendments[amendment_id])


# ── Power Balance ──────────────────────────────────────────────────────────

@app.get("/v1/power-balance")
def power_balance_overview():
    balance = _power_balance()
    entry = {**balance, "timestamp": _now()}
    power_log.append(entry)
    if len(power_log) > 5000:
        power_log.pop(0)
    return balance


@app.get("/v1/power-balance/alerts")
def power_alerts():
    balance = _power_balance()
    return {"alerts": balance["concentration_alerts"]}


# ── Governance Health ──────────────────────────────────────────────────────

@app.get("/v1/governance-health")
def governance_health():
    active_members = [m for m in members.values() if m.active]
    total_voting = sum(1 for m in active_members if m.role in (CouncilRole.chair, CouncilRole.voting_member))
    total_votes = sum(m.votes_cast for m in active_members)
    participation_rate = round(total_votes / max(total_voting * max(len(amendments), 1), 1), 4)

    # Amendment velocity: amendments enacted
    enacted = sum(1 for a in amendments.values() if a.stage == AmendmentStage.enacted)

    # Coherence: % of articles with valid cross-refs
    valid_refs = 0
    total_refs = 0
    for a in articles.values():
        for r in a.cross_references:
            total_refs += 1
            if r in articles:
                valid_refs += 1
    coherence = round(valid_refs / max(total_refs, 1), 4)

    # Power Gini
    balance = _power_balance()
    all_weights = []
    for d_info in balance["domains"].values():
        all_weights.extend(d_info["holders"].values())
    all_weights.sort()
    n = len(all_weights)
    total_w = sum(all_weights) or 1.0
    gini_sum = sum((2 * (i + 1) - n - 1) * w for i, w in enumerate(all_weights))
    gini = round(abs(gini_sum / (n * total_w)) if n > 1 else 0.0, 4)

    # Transparency index (all articles accessible = 1.0 for now)
    transparency = 1.0

    snapshot = {
        "participation_rate": participation_rate,
        "amendment_velocity": enacted,
        "coherence_score": coherence,
        "power_gini": gini,
        "transparency_index": transparency,
        "active_members": len(active_members),
        "total_articles": len(articles),
        "concentration_alerts": len(balance["concentration_alerts"]),
        "timestamp": _now(),
    }
    governance_snapshots.append(snapshot)
    if len(governance_snapshots) > 5000:
        governance_snapshots.pop(0)
    return snapshot


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/v1/analytics")
def analytics():
    stage_dist: Dict[str, int] = defaultdict(int)
    type_dist: Dict[str, int] = defaultdict(int)
    for a in amendments.values():
        stage_dist[a.stage.value] += 1
        type_dist[a.amendment_type.value] += 1
    role_dist: Dict[str, int] = defaultdict(int)
    for m in members.values():
        if m.active:
            role_dist[m.role.value] += 1
    category_dist: Dict[str, int] = defaultdict(int)
    for a in articles.values():
        category_dist[a.category.value] += 1
    return {
        "articles": {
            "total": len(articles),
            "by_category": dict(category_dist),
        },
        "members": {
            "total": len(members),
            "active": sum(1 for m in members.values() if m.active),
            "by_role": dict(role_dist),
        },
        "amendments": {
            "total": len(amendments),
            "by_stage": dict(stage_dist),
            "by_type": dict(type_dist),
        },
        "power_log_entries": len(power_log),
        "governance_snapshots": len(governance_snapshots),
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9304)
