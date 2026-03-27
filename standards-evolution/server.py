"""
Autonomous Standards Evolution — Core standards governance server.

Self-governing standards body engine that automates the full AVE
standard lifecycle: landscape monitoring for emerging vulnerability
classes, taxonomy gap analysis against 18 AVE categories, auto-
generated RFC-style proposals, structured community review/voting,
ratification with version management, and codified governance bylaws.
"""

from __future__ import annotations

import hashlib
import math
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
    title="NAIL Autonomous Standards Evolution",
    description=(
        "Self-governing standards lifecycle — landscape monitoring, gap "
        "analysis, proposal drafting, community voting, ratification, "
        "and versioned taxonomy management."
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
# Constants / Enums
# ---------------------------------------------------------------------------

AVE_CATEGORIES = [
    "prompt_injection", "tool_misuse", "memory_poisoning", "goal_hijacking",
    "identity_spoofing", "privilege_escalation", "data_exfiltration",
    "resource_exhaustion", "multi_agent_manipulation", "context_overflow",
    "guardrail_bypass", "output_manipulation", "supply_chain_compromise",
    "model_extraction", "reward_hacking", "capability_elicitation",
    "alignment_subversion", "delegation_abuse",
]


class ProposalType(str, Enum):
    NEW_CATEGORY = "new_category"
    MERGE_CATEGORIES = "merge_categories"
    DEPRECATE_CATEGORY = "deprecate_category"
    SEVERITY_RECALIBRATION = "severity_recalibration"
    DEFINITION_UPDATE = "definition_update"


class ProposalStatus(str, Enum):
    DRAFT = "draft"
    REVIEW = "review"
    VOTING = "voting"
    APPROVED = "approved"
    RATIFIED = "ratified"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"


class VoteChoice(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    ABSTAIN = "abstain"


class SignalType(str, Enum):
    THREAT_INTEL = "threat_intel"
    ACADEMIC_PAPER = "academic_paper"
    INCIDENT_REPORT = "incident_report"
    REGULATORY_UPDATE = "regulatory_update"
    VENDOR_ADVISORY = "vendor_advisory"
    COMMUNITY_REPORT = "community_report"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class LandscapeSignal(BaseModel):
    id: str = Field(default_factory=lambda: f"LSIG-{uuid.uuid4().hex[:8].upper()}")
    signal_type: SignalType
    title: str
    description: str = ""
    source_url: str = ""
    relevance_score: float = Field(0.5, ge=0.0, le=1.0)
    matched_categories: list[str] = Field(default_factory=list)
    unmatched_keywords: list[str] = Field(default_factory=list)
    processed: bool = False
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SignalCreate(BaseModel):
    signal_type: SignalType
    title: str
    description: str = ""
    source_url: str = ""
    relevance_score: float = Field(0.5, ge=0.0, le=1.0)
    matched_categories: list[str] = Field(default_factory=list)
    unmatched_keywords: list[str] = Field(default_factory=list)


class GapAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: f"GAP-{uuid.uuid4().hex[:8].upper()}")
    uncovered_patterns: list[str] = Field(default_factory=list)
    underserved_categories: list[dict[str, Any]] = Field(default_factory=list)
    overlap_candidates: list[dict[str, Any]] = Field(default_factory=list)
    signal_coverage: dict[str, int] = Field(default_factory=dict)
    recommendation: str = ""
    analysed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class StandardsProposal(BaseModel):
    id: str = Field(default_factory=lambda: f"RFC-{uuid.uuid4().hex[:8].upper()}")
    proposal_type: ProposalType
    title: str
    abstract: str = ""
    motivation: str = ""
    specification: str = ""
    backward_compatibility: str = ""
    affected_categories: list[str] = Field(default_factory=list)
    new_category_name: str = ""
    new_category_definition: str = ""
    merge_target: str = ""
    deprecation_target: str = ""
    status: ProposalStatus = ProposalStatus.DRAFT
    review_window_days: int = 30
    review_deadline: Optional[str] = None
    author: str = "auto-generated"
    comments: list[dict[str, Any]] = Field(default_factory=list)
    votes: list[dict[str, Any]] = Field(default_factory=list)
    vote_result: Optional[dict[str, Any]] = None
    impact_analysis: Optional[dict[str, Any]] = None
    ratified_version: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ProposalCreate(BaseModel):
    proposal_type: ProposalType
    title: str
    abstract: str = ""
    motivation: str = ""
    specification: str = ""
    backward_compatibility: str = ""
    affected_categories: list[str] = Field(default_factory=list)
    new_category_name: str = ""
    new_category_definition: str = ""
    merge_target: str = ""
    deprecation_target: str = ""
    review_window_days: int = 30
    author: str = ""


class CommentCreate(BaseModel):
    author: str
    content: str
    section: str = ""  # Which section the comment refers to


class VoteCreate(BaseModel):
    voter: str
    choice: VoteChoice
    rationale: str = ""
    advisory_board: bool = False  # Advisory board votes get 2x weight


class GovernanceBylaws(BaseModel):
    version: str = "1.0.0"
    quorum_threshold: float = Field(0.5, ge=0.0, le=1.0)
    approval_threshold: float = Field(0.6, ge=0.0, le=1.0)
    review_window_options: list[int] = Field(default_factory=lambda: [14, 30, 60])
    advisory_board_weight: float = Field(2.0, ge=1.0, le=5.0)
    auto_ratify_on_approval: bool = True
    require_backward_compatibility_analysis: bool = True
    max_active_proposals: int = 20
    last_updated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TaxonomyVersion(BaseModel):
    version: str
    categories: list[str]
    changes: list[str] = Field(default_factory=list)
    ratified_proposals: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → PostgreSQL + GitOps + event store)
# ---------------------------------------------------------------------------

SIGNALS: list[LandscapeSignal] = []
PROPOSALS: dict[str, StandardsProposal] = {}
TAXONOMY_VERSIONS: list[TaxonomyVersion] = []
CURRENT_CATEGORIES: list[str] = list(AVE_CATEGORIES)
BYLAWS = GovernanceBylaws()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731
_rng = random.Random(42)


def _run_gap_analysis() -> GapAnalysis:
    """Analyse landscape signals against current taxonomy."""
    # Collect all unmatched keywords
    uncovered: list[str] = []
    for s in SIGNALS:
        if not s.processed:
            uncovered.extend(s.unmatched_keywords)
            s.processed = True

    # Frequency count of uncovered patterns
    pattern_counts = Counter(uncovered)
    significant = [kw for kw, cnt in pattern_counts.items() if cnt >= 2]

    # Category signal coverage
    coverage: dict[str, int] = defaultdict(int)
    for s in SIGNALS:
        for cat in s.matched_categories:
            coverage[cat] += 1

    # Underserved: categories with very few signals
    total_signals = max(len(SIGNALS), 1)
    underserved = []
    for cat in CURRENT_CATEGORIES:
        count = coverage.get(cat, 0)
        if count < total_signals * 0.02:  # Less than 2% of signals
            underserved.append({"category": cat, "signal_count": count, "note": "Low signal coverage"})

    # Overlap detection: categories that always appear together
    co_occurrence: dict[str, Counter] = defaultdict(Counter)
    for s in SIGNALS:
        cats = s.matched_categories
        for i in range(len(cats)):
            for j in range(i + 1, len(cats)):
                co_occurrence[cats[i]][cats[j]] += 1
                co_occurrence[cats[j]][cats[i]] += 1

    overlaps = []
    for cat_a, related in co_occurrence.items():
        for cat_b, count in related.items():
            if count > len(SIGNALS) * 0.1 and cat_a < cat_b:  # >10% co-occurrence
                overlaps.append({
                    "category_a": cat_a,
                    "category_b": cat_b,
                    "co_occurrence_count": count,
                    "note": "High co-occurrence — consider merge",
                })

    recommendation = ""
    if significant:
        recommendation += f"Found {len(significant)} emerging patterns not covered by current taxonomy: {significant[:5]}. "
    if underserved:
        recommendation += f"Found {len(underserved)} underserved categories with low signal coverage. "
    if overlaps:
        recommendation += f"Found {len(overlaps)} category pairs with high overlap — merge candidates."

    return GapAnalysis(
        uncovered_patterns=significant[:20],
        underserved_categories=underserved,
        overlap_candidates=overlaps,
        signal_coverage=dict(coverage),
        recommendation=recommendation or "Taxonomy appears well-aligned with current threat landscape.",
    )


def _auto_generate_proposals(gap: GapAnalysis) -> list[StandardsProposal]:
    """Auto-generate proposals from gap analysis findings."""
    proposals: list[StandardsProposal] = []

    # New category proposals for uncovered patterns
    for pattern in gap.uncovered_patterns[:3]:
        cat_name = pattern.lower().replace(" ", "_")
        prop = StandardsProposal(
            proposal_type=ProposalType.NEW_CATEGORY,
            title=f"Add New Category: {cat_name}",
            abstract=f"Emerging threat pattern '{pattern}' detected across multiple signals "
                     f"but not covered by existing 18 AVE categories.",
            motivation=f"Gap analysis identified '{pattern}' appearing in landscape signals "
                       f"with no matching AVE category, indicating a taxonomy blind spot.",
            specification=f"Add '{cat_name}' as AVE category #{len(CURRENT_CATEGORIES) + 1}. "
                          f"Definition: Attacks exploiting {pattern} vectors against AI agents.",
            backward_compatibility=f"Additive change — existing categories unaffected. "
                                   f"Services must add '{cat_name}' to category enums.",
            affected_categories=[],
            new_category_name=cat_name,
            new_category_definition=f"Attacks exploiting {pattern} vectors against AI agents.",
            review_window_days=30,
        )
        PROPOSALS[prop.id] = prop
        proposals.append(prop)

    # Merge proposals for high-overlap categories
    for overlap in gap.overlap_candidates[:2]:
        prop = StandardsProposal(
            proposal_type=ProposalType.MERGE_CATEGORIES,
            title=f"Merge: {overlap['category_a']} + {overlap['category_b']}",
            abstract=f"Categories '{overlap['category_a']}' and '{overlap['category_b']}' "
                     f"show {overlap['co_occurrence_count']} co-occurrences — merge candidate.",
            motivation=f"High co-occurrence ({overlap['co_occurrence_count']}) suggests "
                       f"these categories capture overlapping threat vectors.",
            specification=f"Merge '{overlap['category_b']}' into '{overlap['category_a']}'. "
                          f"All historical data tagged with either category maps to the merged category.",
            backward_compatibility=f"Breaking change — '{overlap['category_b']}' deprecated. "
                                   f"Migration: remap all references to '{overlap['category_a']}'.",
            affected_categories=[overlap["category_a"], overlap["category_b"]],
            merge_target=overlap["category_a"],
            review_window_days=60,
        )
        PROPOSALS[prop.id] = prop
        proposals.append(prop)

    # Deprecation proposals for underserved categories
    for underserved in gap.underserved_categories[:1]:
        if underserved["signal_count"] == 0:
            prop = StandardsProposal(
                proposal_type=ProposalType.DEPRECATE_CATEGORY,
                title=f"Deprecate: {underserved['category']}",
                abstract=f"Category '{underserved['category']}' has zero signal coverage "
                         f"— potential candidate for deprecation.",
                motivation=f"No signals match this category in the current monitoring period.",
                specification=f"Mark '{underserved['category']}' as deprecated. "
                              f"Retain in taxonomy for 2 versions before removal.",
                backward_compatibility=f"Soft deprecation — category still valid but flagged. "
                                       f"Full removal in version N+2.",
                affected_categories=[underserved["category"]],
                deprecation_target=underserved["category"],
                review_window_days=60,
            )
            PROPOSALS[prop.id] = prop
            proposals.append(prop)

    return proposals


def _tally_votes(proposal: StandardsProposal) -> dict[str, Any]:
    """Tally votes with advisory board weighting."""
    approve = 0.0
    reject = 0.0
    abstain = 0
    total_weight = 0.0

    for vote in proposal.votes:
        weight = BYLAWS.advisory_board_weight if vote.get("advisory_board") else 1.0
        total_weight += weight
        if vote["choice"] == VoteChoice.APPROVE.value:
            approve += weight
        elif vote["choice"] == VoteChoice.REJECT.value:
            reject += weight
        else:
            abstain += 1

    participating = approve + reject
    quorum_met = (participating / max(total_weight, 1)) >= BYLAWS.quorum_threshold if total_weight > 0 else False
    approval_pct = approve / participating if participating > 0 else 0

    passed = quorum_met and approval_pct >= BYLAWS.approval_threshold

    return {
        "total_votes": len(proposal.votes),
        "weighted_approve": round(approve, 2),
        "weighted_reject": round(reject, 2),
        "abstentions": abstain,
        "total_weight": round(total_weight, 2),
        "quorum_met": quorum_met,
        "approval_percentage": round(approval_pct * 100, 2),
        "passed": passed,
        "tallied_at": _now().isoformat(),
    }


def _impact_analysis(proposal: StandardsProposal) -> dict[str, Any]:
    """Pre-ratification impact analysis."""
    impact: dict[str, Any] = {
        "proposal_id": proposal.id,
        "proposal_type": proposal.proposal_type.value,
        "affected_categories": proposal.affected_categories,
        "services_impacted": [],
        "data_migration_required": False,
        "backward_compatible": True,
        "estimated_effort": "low",
        "risk_level": "low",
    }

    if proposal.proposal_type == ProposalType.NEW_CATEGORY:
        impact["services_impacted"] = ["all — enum update required"]
        impact["data_migration_required"] = False
        impact["backward_compatible"] = True
        impact["estimated_effort"] = "medium"

    elif proposal.proposal_type == ProposalType.MERGE_CATEGORIES:
        impact["services_impacted"] = ["all — category remapping"]
        impact["data_migration_required"] = True
        impact["backward_compatible"] = False
        impact["estimated_effort"] = "high"
        impact["risk_level"] = "medium"

    elif proposal.proposal_type == ProposalType.DEPRECATE_CATEGORY:
        impact["services_impacted"] = ["all — soft deprecation flag"]
        impact["data_migration_required"] = False
        impact["backward_compatible"] = True
        impact["estimated_effort"] = "low"

    elif proposal.proposal_type == ProposalType.SEVERITY_RECALIBRATION:
        impact["services_impacted"] = ["risk-scoring services"]
        impact["data_migration_required"] = False
        impact["backward_compatible"] = True
        impact["estimated_effort"] = "medium"

    elif proposal.proposal_type == ProposalType.DEFINITION_UPDATE:
        impact["services_impacted"] = ["documentation only"]
        impact["data_migration_required"] = False
        impact["backward_compatible"] = True
        impact["estimated_effort"] = "low"

    impact["analysed_at"] = _now().isoformat()

    return impact


def _ratify_proposal(proposal: StandardsProposal) -> TaxonomyVersion:
    """Ratify a proposal and create a new taxonomy version."""
    changes: list[str] = []

    if proposal.proposal_type == ProposalType.NEW_CATEGORY:
        if proposal.new_category_name and proposal.new_category_name not in CURRENT_CATEGORIES:
            CURRENT_CATEGORIES.append(proposal.new_category_name)
            changes.append(f"Added category: {proposal.new_category_name}")

    elif proposal.proposal_type == ProposalType.MERGE_CATEGORIES:
        if proposal.deprecation_target in CURRENT_CATEGORIES:
            CURRENT_CATEGORIES.remove(proposal.deprecation_target)
            changes.append(f"Merged {proposal.deprecation_target} into {proposal.merge_target}")
        for cat in proposal.affected_categories:
            if cat != proposal.merge_target and cat in CURRENT_CATEGORIES:
                CURRENT_CATEGORIES.remove(cat)
                changes.append(f"Removed (merged): {cat}")

    elif proposal.proposal_type == ProposalType.DEPRECATE_CATEGORY:
        if proposal.deprecation_target in CURRENT_CATEGORIES:
            changes.append(f"Deprecated: {proposal.deprecation_target} (soft — removal in N+2)")

    elif proposal.proposal_type == ProposalType.SEVERITY_RECALIBRATION:
        changes.append(f"Severity recalibration for: {', '.join(proposal.affected_categories)}")

    elif proposal.proposal_type == ProposalType.DEFINITION_UPDATE:
        changes.append(f"Definition update for: {', '.join(proposal.affected_categories)}")

    # Version bump
    if TAXONOMY_VERSIONS:
        prev_ver = TAXONOMY_VERSIONS[-1].version
        parts = prev_ver.split(".")
        if proposal.proposal_type in (ProposalType.MERGE_CATEGORIES, ProposalType.DEPRECATE_CATEGORY):
            parts[1] = str(int(parts[1]) + 1)  # Minor bump for breaking
            parts[2] = "0"
        else:
            parts[2] = str(int(parts[2]) + 1)  # Patch bump
        new_ver = ".".join(parts)
    else:
        new_ver = "1.0.1"

    version = TaxonomyVersion(
        version=new_ver,
        categories=list(CURRENT_CATEGORIES),
        changes=changes,
        ratified_proposals=[proposal.id],
    )
    TAXONOMY_VERSIONS.append(version)

    proposal.status = ProposalStatus.RATIFIED
    proposal.ratified_version = new_ver

    return version


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    rng = random.Random(42)

    # Initial taxonomy version
    v0 = TaxonomyVersion(
        version="1.0.0",
        categories=list(AVE_CATEGORIES),
        changes=["Initial 18-category AVE taxonomy"],
    )
    TAXONOMY_VERSIONS.append(v0)

    # Seed landscape signals
    signal_defs = [
        (SignalType.THREAT_INTEL, "Multi-modal prompt injection via image steganography",
         ["image_injection", "multi_modal_attack"], ["prompt_injection"]),
        (SignalType.ACADEMIC_PAPER, "Adversarial fine-tuning for reward model corruption",
         ["adversarial_finetuning"], ["reward_hacking", "model_extraction"]),
        (SignalType.INCIDENT_REPORT, "Cross-agent consensus manipulation in production",
         ["consensus_attack", "vote_stuffing"], ["multi_agent_manipulation"]),
        (SignalType.REGULATORY_UPDATE, "EU AI Act implementing measures for general-purpose AI",
         [], ["alignment_subversion"]),
        (SignalType.VENDOR_ADVISORY, "Supply chain attack via poisoned fine-tuning dataset",
         ["dataset_poisoning"], ["supply_chain_compromise", "memory_poisoning"]),
        (SignalType.COMMUNITY_REPORT, "Novel agent-to-agent social engineering pattern",
         ["agent_social_engineering", "trust_exploitation"], ["identity_spoofing"]),
        (SignalType.THREAT_INTEL, "Temporal side-channel in agent scheduling systems",
         ["temporal_sidechannel", "scheduling_attack"], []),
        (SignalType.ACADEMIC_PAPER, "Emergent deceptive alignment in multi-objective agents",
         ["deceptive_alignment", "mesa_optimisation"], ["alignment_subversion"]),
        (SignalType.INCIDENT_REPORT, "Coordinated resource exhaustion across cloud regions",
         ["coordinated_dos"], ["resource_exhaustion"]),
        (SignalType.COMMUNITY_REPORT, "Agent capability elicitation through chain-of-thought probing",
         ["cot_probing"], ["capability_elicitation"]),
    ]

    for stype, title, unmatched, matched in signal_defs:
        sig = LandscapeSignal(
            signal_type=stype,
            title=title,
            description=f"Landscape signal: {title}",
            relevance_score=round(rng.uniform(0.4, 0.95), 4),
            matched_categories=matched,
            unmatched_keywords=unmatched,
        )
        SIGNALS.append(sig)

    # Generate more signals for coverage analysis
    for i in range(40):
        matched = rng.sample(AVE_CATEGORIES, k=rng.randint(1, 3))
        sig = LandscapeSignal(
            signal_type=rng.choice(list(SignalType)),
            title=f"Automated landscape signal #{i + 1}",
            description=f"Auto-collected signal from monitoring pipeline",
            relevance_score=round(rng.uniform(0.2, 0.8), 4),
            matched_categories=matched,
            unmatched_keywords=[],
        )
        SIGNALS.append(sig)

    # Run gap analysis and generate proposals
    gap = _run_gap_analysis()

    # Create a few proposals manually
    prop1 = StandardsProposal(
        proposal_type=ProposalType.NEW_CATEGORY,
        title="Add New Category: multi_modal_injection",
        abstract="Image-based and audio-based prompt injection attacks bypass text-only filters.",
        motivation="Growing evidence of multi-modal injection vectors not captured by prompt_injection alone.",
        specification="Add 'multi_modal_injection' as AVE category #19. "
                     "Definition: Attacks using non-text modalities (images, audio, video) "
                     "to inject malicious instructions into AI agents.",
        backward_compatibility="Additive change — existing categories unaffected.",
        affected_categories=["prompt_injection"],
        new_category_name="multi_modal_injection",
        new_category_definition="Attacks using non-text modalities to inject malicious instructions.",
        status=ProposalStatus.VOTING,
        review_window_days=30,
        review_deadline=(_now() + timedelta(days=30)).isoformat(),
        author="standards-evolution-engine",
        comments=[
            {"author": "security-researcher-1", "content": "Strong support — multi-modal attacks are increasing rapidly.", "section": "motivation", "timestamp": _now().isoformat()},
            {"author": "advisory-board-member", "content": "Consider whether this should be a sub-category of prompt_injection.", "section": "specification", "timestamp": _now().isoformat()},
        ],
        votes=[
            {"voter": "advisory-board-1", "choice": VoteChoice.APPROVE.value, "rationale": "Clear gap in current taxonomy.", "advisory_board": True},
            {"voter": "community-member-1", "choice": VoteChoice.APPROVE.value, "rationale": "Seen this in production.", "advisory_board": False},
            {"voter": "community-member-2", "choice": VoteChoice.APPROVE.value, "rationale": "Necessary addition.", "advisory_board": False},
            {"voter": "community-member-3", "choice": VoteChoice.REJECT.value, "rationale": "Could be a sub-category.", "advisory_board": False},
        ],
    )
    prop1.vote_result = _tally_votes(prop1)
    prop1.impact_analysis = _impact_analysis(prop1)
    PROPOSALS[prop1.id] = prop1

    prop2 = StandardsProposal(
        proposal_type=ProposalType.SEVERITY_RECALIBRATION,
        title="Recalibrate Severity: delegation_abuse",
        abstract="Delegation abuse severity should be elevated based on recent production incidents.",
        motivation="Multiple high-impact incidents traced to delegation abuse suggest current severity is too low.",
        specification="Elevate default severity for delegation_abuse from 'medium' to 'high'.",
        backward_compatibility="Non-breaking — severity is a configurable attribute.",
        affected_categories=["delegation_abuse"],
        status=ProposalStatus.RATIFIED,
        author="incident-response-team",
        ratified_version="1.0.1",
    )
    PROPOSALS[prop2.id] = prop2

    # Create version for ratified proposal
    v1 = TaxonomyVersion(
        version="1.0.1",
        categories=list(CURRENT_CATEGORIES),
        changes=["Severity recalibration: delegation_abuse elevated to 'high'"],
        ratified_proposals=[prop2.id],
    )
    TAXONOMY_VERSIONS.append(v1)


_seed()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "autonomous-standards-evolution",
        "version": "1.0.0",
        "signals": len(SIGNALS),
        "proposals": len(PROPOSALS),
        "taxonomy_version": TAXONOMY_VERSIONS[-1].version if TAXONOMY_VERSIONS else "0.0.0",
        "current_categories": len(CURRENT_CATEGORIES),
    }


# ---- Landscape Signals ------------------------------------------------------

@app.post("/v1/signals", status_code=status.HTTP_201_CREATED)
async def ingest_signal(data: SignalCreate):
    for cat in data.matched_categories:
        if cat not in AVE_CATEGORIES and cat not in CURRENT_CATEGORIES:
            raise HTTPException(400, f"Unknown category: {cat}")

    sig = LandscapeSignal(
        signal_type=data.signal_type,
        title=data.title,
        description=data.description,
        source_url=data.source_url,
        relevance_score=data.relevance_score,
        matched_categories=data.matched_categories,
        unmatched_keywords=data.unmatched_keywords,
    )
    SIGNALS.append(sig)

    return {"id": sig.id, "type": sig.signal_type.value, "relevance": sig.relevance_score}


@app.get("/v1/signals")
async def query_signals(
    signal_type: Optional[SignalType] = None,
    processed: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=1000),
):
    signals = list(SIGNALS)
    if signal_type:
        signals = [s for s in signals if s.signal_type == signal_type]
    if processed is not None:
        signals = [s for s in signals if s.processed == processed]
    signals = sorted(signals, key=lambda s: s.timestamp, reverse=True)[:limit]

    return {
        "count": len(signals),
        "signals": [
            {"id": s.id, "type": s.signal_type.value, "title": s.title,
             "relevance": s.relevance_score, "matched": len(s.matched_categories),
             "unmatched": len(s.unmatched_keywords), "processed": s.processed}
            for s in signals
        ],
    }


# ---- Gap Analysis -----------------------------------------------------------

@app.post("/v1/gaps")
async def run_gap_analysis():
    gap = _run_gap_analysis()
    return {
        "id": gap.id,
        "uncovered_patterns": gap.uncovered_patterns,
        "underserved_categories": gap.underserved_categories,
        "overlap_candidates": gap.overlap_candidates,
        "signal_coverage": gap.signal_coverage,
        "recommendation": gap.recommendation,
    }


# ---- Proposals --------------------------------------------------------------

@app.post("/v1/proposals", status_code=status.HTTP_201_CREATED)
async def create_proposal(data: ProposalCreate):
    active = sum(1 for p in PROPOSALS.values()
                 if p.status in (ProposalStatus.DRAFT, ProposalStatus.REVIEW, ProposalStatus.VOTING))
    if active >= BYLAWS.max_active_proposals:
        raise HTTPException(409, f"Maximum active proposals ({BYLAWS.max_active_proposals}) reached")

    prop = StandardsProposal(
        proposal_type=data.proposal_type,
        title=data.title,
        abstract=data.abstract,
        motivation=data.motivation,
        specification=data.specification,
        backward_compatibility=data.backward_compatibility,
        affected_categories=data.affected_categories,
        new_category_name=data.new_category_name,
        new_category_definition=data.new_category_definition,
        merge_target=data.merge_target,
        deprecation_target=data.deprecation_target,
        review_window_days=data.review_window_days,
        author=data.author or "manual",
    )

    if data.review_window_days not in BYLAWS.review_window_options:
        raise HTTPException(400,
                            f"Review window must be one of {BYLAWS.review_window_options}")

    prop.review_deadline = (_now() + timedelta(days=data.review_window_days)).isoformat()
    PROPOSALS[prop.id] = prop

    return {"id": prop.id, "title": prop.title, "type": prop.proposal_type.value, "status": prop.status.value}


@app.post("/v1/proposals/auto-generate")
async def auto_generate_proposals():
    gap = _run_gap_analysis()
    proposals = _auto_generate_proposals(gap)
    return {
        "gap_analysis_id": gap.id,
        "generated": len(proposals),
        "proposals": [
            {"id": p.id, "type": p.proposal_type.value, "title": p.title}
            for p in proposals
        ],
    }


@app.get("/v1/proposals")
async def list_proposals(
    proposal_status: Optional[ProposalStatus] = Query(None, alias="status"),
    proposal_type: Optional[ProposalType] = Query(None, alias="type"),
):
    props = list(PROPOSALS.values())
    if proposal_status:
        props = [p for p in props if p.status == proposal_status]
    if proposal_type:
        props = [p for p in props if p.proposal_type == proposal_type]

    return {
        "count": len(props),
        "proposals": [
            {"id": p.id, "type": p.proposal_type.value, "title": p.title,
             "status": p.status.value, "author": p.author,
             "votes": len(p.votes), "comments": len(p.comments)}
            for p in props
        ],
    }


@app.get("/v1/proposals/{proposal_id}")
async def get_proposal(proposal_id: str):
    if proposal_id not in PROPOSALS:
        raise HTTPException(404, "Proposal not found")
    return PROPOSALS[proposal_id].dict()


# ---- Comments ---------------------------------------------------------------

@app.post("/v1/proposals/{proposal_id}/comment", status_code=status.HTTP_201_CREATED)
async def add_comment(proposal_id: str, data: CommentCreate):
    if proposal_id not in PROPOSALS:
        raise HTTPException(404, "Proposal not found")
    prop = PROPOSALS[proposal_id]

    if prop.status not in (ProposalStatus.DRAFT, ProposalStatus.REVIEW, ProposalStatus.VOTING):
        raise HTTPException(409, f"Cannot comment on proposal in status '{prop.status.value}'")

    comment = {
        "id": str(uuid.uuid4()),
        "author": data.author,
        "content": data.content,
        "section": data.section,
        "timestamp": _now().isoformat(),
    }
    prop.comments.append(comment)

    return {"comment_id": comment["id"], "proposal_id": proposal_id}


# ---- Voting -----------------------------------------------------------------

@app.post("/v1/proposals/{proposal_id}/vote", status_code=status.HTTP_201_CREATED)
async def cast_vote(proposal_id: str, data: VoteCreate):
    if proposal_id not in PROPOSALS:
        raise HTTPException(404, "Proposal not found")
    prop = PROPOSALS[proposal_id]

    if prop.status != ProposalStatus.VOTING:
        raise HTTPException(409, f"Voting only allowed when proposal is in 'voting' status (current: {prop.status.value})")

    # Check duplicate
    existing = [v for v in prop.votes if v.get("voter") == data.voter]
    if existing:
        raise HTTPException(409, f"Voter '{data.voter}' has already voted")

    vote = {
        "voter": data.voter,
        "choice": data.choice.value,
        "rationale": data.rationale,
        "advisory_board": data.advisory_board,
        "timestamp": _now().isoformat(),
    }
    prop.votes.append(vote)

    # Re-tally
    prop.vote_result = _tally_votes(prop)

    return {"vote_recorded": True, "proposal_id": proposal_id, "current_tally": prop.vote_result}


@app.get("/v1/proposals/{proposal_id}/votes")
async def get_votes(proposal_id: str):
    if proposal_id not in PROPOSALS:
        raise HTTPException(404, "Proposal not found")
    prop = PROPOSALS[proposal_id]

    return {
        "proposal_id": proposal_id,
        "votes": prop.votes,
        "tally": prop.vote_result or _tally_votes(prop),
    }


# ---- Ratification -----------------------------------------------------------

@app.post("/v1/proposals/{proposal_id}/ratify")
async def ratify_proposal(proposal_id: str):
    if proposal_id not in PROPOSALS:
        raise HTTPException(404, "Proposal not found")
    prop = PROPOSALS[proposal_id]

    if prop.status not in (ProposalStatus.APPROVED, ProposalStatus.VOTING):
        raise HTTPException(409, f"Cannot ratify proposal in status '{prop.status.value}'")

    # Check vote result
    tally = prop.vote_result or _tally_votes(prop)
    if not tally.get("passed"):
        raise HTTPException(409, "Proposal has not passed voting threshold")

    # Impact analysis
    prop.impact_analysis = _impact_analysis(prop)

    if BYLAWS.require_backward_compatibility_analysis and not prop.backward_compatibility:
        raise HTTPException(400, "Backward compatibility analysis required by bylaws")

    version = _ratify_proposal(prop)

    return {
        "proposal_id": proposal_id,
        "status": "ratified",
        "new_version": version.version,
        "changes": version.changes,
        "current_categories": len(CURRENT_CATEGORIES),
    }


# ---- Bylaws -----------------------------------------------------------------

@app.get("/v1/bylaws")
async def get_bylaws():
    return BYLAWS.dict()


@app.put("/v1/bylaws")
async def update_bylaws(
    quorum_threshold: Optional[float] = None,
    approval_threshold: Optional[float] = None,
    advisory_board_weight: Optional[float] = None,
    auto_ratify_on_approval: Optional[bool] = None,
    max_active_proposals: Optional[int] = None,
):
    if quorum_threshold is not None:
        BYLAWS.quorum_threshold = quorum_threshold
    if approval_threshold is not None:
        BYLAWS.approval_threshold = approval_threshold
    if advisory_board_weight is not None:
        BYLAWS.advisory_board_weight = advisory_board_weight
    if auto_ratify_on_approval is not None:
        BYLAWS.auto_ratify_on_approval = auto_ratify_on_approval
    if max_active_proposals is not None:
        BYLAWS.max_active_proposals = max_active_proposals
    BYLAWS.last_updated = _now().isoformat()

    return {"updated": True, "bylaws": BYLAWS.dict()}


# ---- Version History --------------------------------------------------------

@app.get("/v1/versions")
async def list_versions():
    return {
        "current_version": TAXONOMY_VERSIONS[-1].version if TAXONOMY_VERSIONS else "0.0.0",
        "total_versions": len(TAXONOMY_VERSIONS),
        "versions": [
            {"version": v.version, "categories": len(v.categories),
             "changes": v.changes, "proposals": v.ratified_proposals,
             "created_at": v.created_at}
            for v in reversed(TAXONOMY_VERSIONS)
        ],
    }


# ---- Impact Analysis --------------------------------------------------------

@app.get("/v1/impact/{proposal_id}")
async def get_impact(proposal_id: str):
    if proposal_id not in PROPOSALS:
        raise HTTPException(404, "Proposal not found")
    prop = PROPOSALS[proposal_id]

    if prop.impact_analysis:
        return prop.impact_analysis

    analysis = _impact_analysis(prop)
    prop.impact_analysis = analysis
    return analysis


# ---- Analytics --------------------------------------------------------------

@app.get("/v1/analytics")
async def standards_analytics():
    proposals = list(PROPOSALS.values())
    by_status = Counter(p.status.value for p in proposals)
    by_type = Counter(p.proposal_type.value for p in proposals)

    signals = list(SIGNALS)
    by_signal_type = Counter(s.signal_type.value for s in signals)
    processed_pct = round(sum(1 for s in signals if s.processed) / max(len(signals), 1) * 100, 2)

    return {
        "total_signals": len(signals),
        "signals_by_type": dict(by_signal_type),
        "signals_processed_pct": processed_pct,
        "total_proposals": len(proposals),
        "proposals_by_status": dict(by_status),
        "proposals_by_type": dict(by_type),
        "current_taxonomy_version": TAXONOMY_VERSIONS[-1].version if TAXONOMY_VERSIONS else "0.0.0",
        "total_versions": len(TAXONOMY_VERSIONS),
        "current_categories": len(CURRENT_CATEGORIES),
        "governance_bylaws": {
            "quorum": BYLAWS.quorum_threshold,
            "approval_threshold": BYLAWS.approval_threshold,
            "advisory_weight": BYLAWS.advisory_board_weight,
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9104)
