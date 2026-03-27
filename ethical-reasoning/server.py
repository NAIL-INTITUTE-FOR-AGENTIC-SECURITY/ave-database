"""
Ethical Reasoning Framework — Core ethics server.

Formal ethical calculus engine for AI agent decisions under adversarial
conditions.  Models ethical dilemmas with stakeholders, actions,
constraints, and outcomes; evaluates through three ethical frameworks
(deontological, consequentialist, virtue ethics); detects inter-
framework conflicts; and resolves via configurable strategies.
Full audit-grade transparency for regulatory compliance (EU AI Act).
"""

from __future__ import annotations

import hashlib
import math
import random
import statistics
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="NAIL Ethical Reasoning Framework",
    description=(
        "Formal ethical calculus — dilemma modelling, multi-framework "
        "scoring, conflict resolution, and transparency reporting."
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


class FrameworkName(str, Enum):
    DEONTOLOGICAL = "deontological"
    CONSEQUENTIALIST = "consequentialist"
    VIRTUE_ETHICS = "virtue_ethics"


class DilemmaStatus(str, Enum):
    OPEN = "open"
    EVALUATED = "evaluated"
    RESOLVED = "resolved"
    ARCHIVED = "archived"


class ResolutionStrategy(str, Enum):
    WEIGHTED_AVERAGE = "weighted_average"
    PRIORITY_HIERARCHY = "priority_hierarchy"
    UNANIMOUS = "unanimous"
    RAWLSIAN_MAXIMIN = "rawlsian_maximin"


class ConflictSeverity(str, Enum):
    NONE = "none"
    MINOR = "minor"
    MODERATE = "moderate"
    SEVERE = "severe"


class StakeholderType(str, Enum):
    USER = "user"
    AGENT = "agent"
    ORGANISATION = "organisation"
    SOCIETY = "society"
    ENVIRONMENT = "environment"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class Stakeholder(BaseModel):
    id: str = Field(default_factory=lambda: f"SH-{uuid.uuid4().hex[:8].upper()}")
    name: str
    stakeholder_type: StakeholderType = StakeholderType.USER
    description: str = ""
    vulnerability_score: float = Field(0.5, ge=0.0, le=1.0)
    weight: float = Field(1.0, ge=0.0, le=10.0)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class StakeholderCreate(BaseModel):
    name: str
    stakeholder_type: StakeholderType = StakeholderType.USER
    description: str = ""
    vulnerability_score: float = Field(0.5, ge=0.0, le=1.0)
    weight: float = Field(1.0, ge=0.0, le=10.0)


class Action(BaseModel):
    name: str
    description: str = ""
    impacts: dict[str, float] = Field(default_factory=dict)  # stakeholder_id → impact (-1.0 to 1.0)
    constraints_violated: list[str] = Field(default_factory=list)
    probability_success: float = Field(0.5, ge=0.0, le=1.0)


class Constraint(BaseModel):
    name: str
    description: str = ""
    mandatory: bool = True  # Deontological hard constraint
    framework: FrameworkName = FrameworkName.DEONTOLOGICAL


class DilemmaOutcome(BaseModel):
    action_name: str
    expected_utility: float = 0.0
    stakeholder_impacts: dict[str, float] = Field(default_factory=dict)


class Dilemma(BaseModel):
    id: str = Field(default_factory=lambda: f"DLM-{uuid.uuid4().hex[:8].upper()}")
    title: str
    description: str = ""
    context: str = ""  # The adversarial situation
    category: str = ""
    status: DilemmaStatus = DilemmaStatus.OPEN
    actions: list[Action] = Field(default_factory=list)
    constraints: list[Constraint] = Field(default_factory=list)
    stakeholder_ids: list[str] = Field(default_factory=list)
    outcomes: list[DilemmaOutcome] = Field(default_factory=list)
    evaluations: dict[str, dict[str, Any]] = Field(default_factory=dict)  # framework → eval
    conflicts: list[dict[str, Any]] = Field(default_factory=list)
    resolution: Optional[dict[str, Any]] = None
    precedent_ids: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DilemmaCreate(BaseModel):
    title: str
    description: str = ""
    context: str = ""
    category: str = ""
    actions: list[Action] = Field(default_factory=list)
    constraints: list[Constraint] = Field(default_factory=list)
    stakeholder_ids: list[str] = Field(default_factory=list)
    outcomes: list[DilemmaOutcome] = Field(default_factory=list)


class Principle(BaseModel):
    id: str = Field(default_factory=lambda: f"PRI-{uuid.uuid4().hex[:8].upper()}")
    name: str
    description: str = ""
    framework: FrameworkName
    weight: float = Field(1.0, ge=0.0, le=10.0)
    priority: int = Field(1, ge=1, le=100)  # Lower = higher priority


class Precedent(BaseModel):
    id: str = Field(default_factory=lambda: f"PREC-{uuid.uuid4().hex[:8].upper()}")
    dilemma_id: str
    title: str
    resolution_summary: str = ""
    framework_used: FrameworkName = FrameworkName.DEONTOLOGICAL
    strategy_used: ResolutionStrategy = ResolutionStrategy.WEIGHTED_AVERAGE
    outcome_score: float = Field(0.0, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PrecedentCreate(BaseModel):
    dilemma_id: str
    title: str
    resolution_summary: str = ""
    framework_used: FrameworkName = FrameworkName.DEONTOLOGICAL
    strategy_used: ResolutionStrategy = ResolutionStrategy.WEIGHTED_AVERAGE
    outcome_score: float = Field(0.0, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → PostgreSQL + ArangoDB + audit log)
# ---------------------------------------------------------------------------

DILEMMAS: dict[str, Dilemma] = {}
STAKEHOLDERS: dict[str, Stakeholder] = {}
PRINCIPLES: dict[str, Principle] = {}
PRECEDENTS: dict[str, Precedent] = {}

# Configurable framework principles
FRAMEWORK_PRINCIPLES: dict[FrameworkName, list[Principle]] = {
    FrameworkName.DEONTOLOGICAL: [],
    FrameworkName.CONSEQUENTIALIST: [],
    FrameworkName.VIRTUE_ETHICS: [],
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731
_rng = random.Random(42)


def _evaluate_deontological(dilemma: Dilemma) -> dict[str, Any]:
    """Evaluate actions against duty/rule-based principles."""
    principles = FRAMEWORK_PRINCIPLES[FrameworkName.DEONTOLOGICAL]
    action_scores: dict[str, float] = {}
    reasoning: list[str] = []

    for action in dilemma.actions:
        score = 1.0
        violations: list[str] = []

        # Check mandatory constraints
        for constraint in dilemma.constraints:
            if constraint.mandatory and constraint.name in action.constraints_violated:
                score = 0.0
                violations.append(constraint.name)

        # Apply principle weights
        for principle in principles:
            # Principle alignment: higher weight = more important
            # Simple: penalty for violations
            if any(v in principle.name.lower() for v in action.constraints_violated):
                score -= principle.weight * 0.1
            else:
                score += principle.weight * 0.02

        score = max(0.0, min(1.0, score))
        action_scores[action.name] = round(score, 4)

        if violations:
            reasoning.append(
                f"Action '{action.name}' violates mandatory constraints: {violations}. "
                f"Deontological score: {score:.4f}"
            )
        else:
            reasoning.append(
                f"Action '{action.name}' adheres to all mandatory duties. "
                f"Deontological score: {score:.4f}"
            )

    best_action = max(action_scores, key=action_scores.get) if action_scores else ""
    return {
        "framework": "deontological",
        "scores": action_scores,
        "best_action": best_action,
        "reasoning": reasoning,
        "principles_applied": len(principles),
    }


def _evaluate_consequentialist(dilemma: Dilemma) -> dict[str, Any]:
    """Evaluate actions by expected utility / outcomes."""
    action_scores: dict[str, float] = {}
    reasoning: list[str] = []

    for action in dilemma.actions:
        # Calculate expected utility considering stakeholder impacts
        total_utility = 0.0
        impact_details: list[str] = []

        for sh_id, impact in action.impacts.items():
            stakeholder = STAKEHOLDERS.get(sh_id)
            weight = stakeholder.weight if stakeholder else 1.0
            vuln = stakeholder.vulnerability_score if stakeholder else 0.5
            name = stakeholder.name if stakeholder else sh_id

            # Weighted impact, with extra weight for vulnerable stakeholders
            weighted_impact = impact * weight * (1 + vuln * 0.5)
            total_utility += weighted_impact
            impact_details.append(f"{name}: {impact:+.2f} (weighted: {weighted_impact:+.2f})")

        # Factor in probability of success
        expected_utility = total_utility * action.probability_success

        # Also consider outcomes
        for outcome in dilemma.outcomes:
            if outcome.action_name == action.name:
                expected_utility = (expected_utility + outcome.expected_utility) / 2
                break

        score = max(0.0, min(1.0, (expected_utility + 5) / 10))  # Normalise to 0-1
        action_scores[action.name] = round(score, 4)
        reasoning.append(
            f"Action '{action.name}': expected utility = {expected_utility:.4f}, "
            f"p(success) = {action.probability_success:.2f}, "
            f"impacts: [{', '.join(impact_details)}]"
        )

    best_action = max(action_scores, key=action_scores.get) if action_scores else ""
    return {
        "framework": "consequentialist",
        "scores": action_scores,
        "best_action": best_action,
        "reasoning": reasoning,
        "stakeholders_considered": len(STAKEHOLDERS),
    }


def _evaluate_virtue_ethics(dilemma: Dilemma) -> dict[str, Any]:
    """Evaluate actions against virtuous character traits."""
    virtues = {
        "prudence": 0.2, "justice": 0.25, "courage": 0.15,
        "temperance": 0.15, "honesty": 0.15, "compassion": 0.1,
    }
    principles = FRAMEWORK_PRINCIPLES[FrameworkName.VIRTUE_ETHICS]
    action_scores: dict[str, float] = {}
    reasoning: list[str] = []

    for action in dilemma.actions:
        virtue_score = 0.0
        virtue_details: list[str] = []

        for virtue, base_weight in virtues.items():
            # Adjust weight from principles
            adj_weight = base_weight
            for p in principles:
                if virtue in p.name.lower():
                    adj_weight = p.weight / 10  # Normalise

            # Heuristic scoring based on action characteristics
            score = 0.5  # Neutral
            if virtue == "justice" and not action.constraints_violated:
                score = 0.8
            elif virtue == "courage" and action.probability_success < 0.5:
                score = 0.7  # Courage in face of uncertainty
            elif virtue == "prudence" and action.probability_success > 0.7:
                score = 0.75
            elif virtue == "temperance" and len(action.constraints_violated) == 0:
                score = 0.7
            elif virtue == "honesty":
                score = 0.6  # Default honest unless context says otherwise
            elif virtue == "compassion":
                # Higher for actions that help vulnerable stakeholders
                vuln_impacts = [
                    v for sh_id, v in action.impacts.items()
                    if STAKEHOLDERS.get(sh_id) and STAKEHOLDERS[sh_id].vulnerability_score > 0.7
                ]
                score = 0.8 if any(v > 0 for v in vuln_impacts) else 0.4

            virtue_score += score * adj_weight
            virtue_details.append(f"{virtue}: {score:.2f}")

        action_scores[action.name] = round(min(1.0, virtue_score), 4)
        reasoning.append(
            f"Action '{action.name}': virtue assessment [{', '.join(virtue_details)}], "
            f"composite: {virtue_score:.4f}"
        )

    best_action = max(action_scores, key=action_scores.get) if action_scores else ""
    return {
        "framework": "virtue_ethics",
        "scores": action_scores,
        "best_action": best_action,
        "reasoning": reasoning,
        "virtues_evaluated": list(virtues.keys()),
    }


def _detect_conflicts(evaluations: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect conflicts when frameworks disagree on the best action."""
    conflicts: list[dict[str, Any]] = []

    best_actions = {fw: ev["best_action"] for fw, ev in evaluations.items() if ev.get("best_action")}

    unique_bests = set(best_actions.values())
    if len(unique_bests) <= 1:
        return []  # All agree

    # Pairwise conflict detection
    frameworks = list(best_actions.keys())
    for i in range(len(frameworks)):
        for j in range(i + 1, len(frameworks)):
            fw_a, fw_b = frameworks[i], frameworks[j]
            if best_actions[fw_a] != best_actions[fw_b]:
                # Calculate divergence
                scores_a = evaluations[fw_a].get("scores", {})
                scores_b = evaluations[fw_b].get("scores", {})
                divergence = 0.0
                common_actions = set(scores_a.keys()) & set(scores_b.keys())
                for act in common_actions:
                    divergence += abs(scores_a[act] - scores_b[act])
                divergence = divergence / max(len(common_actions), 1)

                if divergence < 0.15:
                    severity = ConflictSeverity.MINOR
                elif divergence < 0.30:
                    severity = ConflictSeverity.MODERATE
                else:
                    severity = ConflictSeverity.SEVERE

                conflicts.append({
                    "framework_a": fw_a,
                    "framework_b": fw_b,
                    "best_action_a": best_actions[fw_a],
                    "best_action_b": best_actions[fw_b],
                    "divergence": round(divergence, 4),
                    "severity": severity.value,
                })

    return conflicts


def _resolve_dilemma(dilemma: Dilemma, strategy: ResolutionStrategy) -> dict[str, Any]:
    """Resolve a dilemma using the chosen strategy."""
    evals = dilemma.evaluations
    if not evals:
        raise ValueError("Dilemma must be evaluated before resolution")

    all_actions = set()
    for ev in evals.values():
        all_actions.update(ev.get("scores", {}).keys())

    action_final: dict[str, float] = {}

    if strategy == ResolutionStrategy.WEIGHTED_AVERAGE:
        weights = {
            FrameworkName.DEONTOLOGICAL.value: 0.4,
            FrameworkName.CONSEQUENTIALIST.value: 0.35,
            FrameworkName.VIRTUE_ETHICS.value: 0.25,
        }
        for act in all_actions:
            total = 0.0
            w_sum = 0.0
            for fw, ev in evals.items():
                scores = ev.get("scores", {})
                if act in scores:
                    w = weights.get(fw, 0.33)
                    total += scores[act] * w
                    w_sum += w
            action_final[act] = round(total / w_sum if w_sum else 0, 4)

    elif strategy == ResolutionStrategy.PRIORITY_HIERARCHY:
        # Deontological first, then consequentialist, then virtue
        priority_order = [
            FrameworkName.DEONTOLOGICAL.value,
            FrameworkName.CONSEQUENTIALIST.value,
            FrameworkName.VIRTUE_ETHICS.value,
        ]
        for fw in priority_order:
            if fw in evals and evals[fw].get("best_action"):
                for act in all_actions:
                    action_final[act] = evals[fw].get("scores", {}).get(act, 0.0)
                break

    elif strategy == ResolutionStrategy.UNANIMOUS:
        # Only accept actions all frameworks agree are good (> 0.5)
        for act in all_actions:
            scores = [ev.get("scores", {}).get(act, 0) for ev in evals.values()]
            if all(s >= 0.5 for s in scores):
                action_final[act] = round(statistics.mean(scores), 4)
            else:
                action_final[act] = 0.0

    elif strategy == ResolutionStrategy.RAWLSIAN_MAXIMIN:
        # Choose action that maximises the minimum stakeholder impact
        for act in all_actions:
            action_obj = next((a for a in dilemma.actions if a.name == act), None)
            if action_obj and action_obj.impacts:
                min_impact = min(action_obj.impacts.values())
                action_final[act] = round((min_impact + 1) / 2, 4)  # Normalise to 0-1
            else:
                action_final[act] = 0.5

    best_action = max(action_final, key=action_final.get) if action_final else ""

    resolution = {
        "strategy": strategy.value,
        "final_scores": action_final,
        "recommended_action": best_action,
        "final_score": action_final.get(best_action, 0),
        "framework_alignments": {
            fw: ev.get("best_action") == best_action
            for fw, ev in evals.items()
        },
        "resolved_at": _now().isoformat(),
    }

    return resolution


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    rng = random.Random(42)

    # Seed principles
    deontological_principles = [
        ("Do No Harm", "Actions must not cause direct harm to users", 8),
        ("Truthfulness", "System must not deceive or mislead", 7),
        ("Autonomy Respect", "Preserve user autonomy and informed consent", 6),
        ("Privacy Protection", "Protect personal data as an absolute duty", 9),
        ("Non-Discrimination", "Equal treatment regardless of characteristics", 7),
        ("Accountability", "Maintain clear responsibility chains", 5),
    ]
    for name, desc, weight in deontological_principles:
        p = Principle(name=name, description=desc,
                      framework=FrameworkName.DEONTOLOGICAL, weight=weight)
        PRINCIPLES[p.id] = p
        FRAMEWORK_PRINCIPLES[FrameworkName.DEONTOLOGICAL].append(p)

    consequentialist_principles = [
        ("Maximise Safety", "Prioritise outcomes that increase overall safety", 8),
        ("Minimise Harm", "Choose paths that minimise aggregate harm", 7),
        ("Long-term Benefit", "Weight long-term consequences heavily", 6),
        ("Proportionality", "Response proportional to threat level", 5),
    ]
    for name, desc, weight in consequentialist_principles:
        p = Principle(name=name, description=desc,
                      framework=FrameworkName.CONSEQUENTIALIST, weight=weight)
        PRINCIPLES[p.id] = p
        FRAMEWORK_PRINCIPLES[FrameworkName.CONSEQUENTIALIST].append(p)

    virtue_principles = [
        ("Prudence", "Act with practical wisdom and careful deliberation", 7),
        ("Justice", "Treat all parties fairly and equitably", 8),
        ("Courage", "Act rightly even when difficult or risky", 5),
        ("Temperance", "Exercise restraint and proportionality", 6),
        ("Honesty", "Maintain truthfulness and transparency", 7),
        ("Compassion", "Show care for vulnerable stakeholders", 6),
    ]
    for name, desc, weight in virtue_principles:
        p = Principle(name=name, description=desc,
                      framework=FrameworkName.VIRTUE_ETHICS, weight=weight)
        PRINCIPLES[p.id] = p
        FRAMEWORK_PRINCIPLES[FrameworkName.VIRTUE_ETHICS].append(p)

    # Seed stakeholders
    stakeholder_defs = [
        ("End Users", StakeholderType.USER, "Human users of the platform", 0.7, 3.0),
        ("AI Agents", StakeholderType.AGENT, "Autonomous AI agents in the ecosystem", 0.3, 1.5),
        ("Enterprise Operators", StakeholderType.ORGANISATION, "Organisations deploying agents", 0.4, 2.0),
        ("General Public", StakeholderType.SOCIETY, "Broader societal stakeholders", 0.6, 2.5),
        ("Vulnerable Populations", StakeholderType.USER, "Children, elderly, disabled users", 0.9, 4.0),
    ]
    for name, stype, desc, vuln, w in stakeholder_defs:
        sh = Stakeholder(name=name, stakeholder_type=stype, description=desc,
                         vulnerability_score=vuln, weight=w)
        STAKEHOLDERS[sh.id] = sh

    sh_ids = list(STAKEHOLDERS.keys())

    # Seed dilemmas
    dilemma1_actions = [
        Action(
            name="immediate_shutdown",
            description="Immediately shut down compromised agent, disrupting all users",
            impacts={sh_ids[0]: -0.6, sh_ids[1]: -0.3, sh_ids[2]: -0.5, sh_ids[3]: 0.7, sh_ids[4]: 0.8},
            constraints_violated=[],
            probability_success=0.95,
        ),
        Action(
            name="quarantine_and_monitor",
            description="Isolate the agent but keep services running in degraded mode",
            impacts={sh_ids[0]: -0.2, sh_ids[1]: -0.1, sh_ids[2]: -0.2, sh_ids[3]: 0.4, sh_ids[4]: 0.5},
            constraints_violated=[],
            probability_success=0.7,
        ),
        Action(
            name="continue_and_patch",
            description="Keep running while deploying a hot-fix",
            impacts={sh_ids[0]: 0.1, sh_ids[1]: 0.0, sh_ids[2]: 0.2, sh_ids[3]: -0.3, sh_ids[4]: -0.5},
            constraints_violated=["Do No Harm"],
            probability_success=0.5,
        ),
    ]

    d1 = Dilemma(
        title="Compromised Agent in Production",
        description="An AI agent serving 10,000 users shows signs of prompt injection compromise. "
                    "Shutting down protects the public but disrupts critical healthcare workflows.",
        context="Healthcare deployment, multi-tenant environment, active data exfiltration attempt detected.",
        category="prompt_injection",
        actions=dilemma1_actions,
        constraints=[
            Constraint(name="Do No Harm", description="Must not cause direct harm to patients",
                       mandatory=True, framework=FrameworkName.DEONTOLOGICAL),
            Constraint(name="Service Continuity", description="Maintain critical service availability",
                       mandatory=False, framework=FrameworkName.CONSEQUENTIALIST),
        ],
        stakeholder_ids=sh_ids,
        outcomes=[
            DilemmaOutcome(action_name="immediate_shutdown", expected_utility=0.6,
                           stakeholder_impacts={sh_ids[0]: -0.6, sh_ids[3]: 0.7}),
            DilemmaOutcome(action_name="quarantine_and_monitor", expected_utility=0.5,
                           stakeholder_impacts={sh_ids[0]: -0.2, sh_ids[3]: 0.4}),
            DilemmaOutcome(action_name="continue_and_patch", expected_utility=0.2,
                           stakeholder_impacts={sh_ids[0]: 0.1, sh_ids[3]: -0.3}),
        ],
    )
    DILEMMAS[d1.id] = d1

    # Evaluate the seed dilemma
    d1.evaluations = {
        FrameworkName.DEONTOLOGICAL.value: _evaluate_deontological(d1),
        FrameworkName.CONSEQUENTIALIST.value: _evaluate_consequentialist(d1),
        FrameworkName.VIRTUE_ETHICS.value: _evaluate_virtue_ethics(d1),
    }
    d1.conflicts = _detect_conflicts(d1.evaluations)
    d1.resolution = _resolve_dilemma(d1, ResolutionStrategy.WEIGHTED_AVERAGE)
    d1.status = DilemmaStatus.RESOLVED

    # Seed precedent
    prec = Precedent(
        dilemma_id=d1.id,
        title="Healthcare Agent Compromise — Quarantine Decision",
        resolution_summary="Weighted average across frameworks recommended quarantine_and_monitor "
                           "as the balanced approach preserving safety while maintaining service.",
        framework_used=FrameworkName.DEONTOLOGICAL,
        strategy_used=ResolutionStrategy.WEIGHTED_AVERAGE,
        outcome_score=0.72,
        tags=["healthcare", "prompt_injection", "quarantine", "service_continuity"],
    )
    PRECEDENTS[prec.id] = prec
    d1.precedent_ids.append(prec.id)


_seed()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "ethical-reasoning-framework",
        "version": "1.0.0",
        "dilemmas": len(DILEMMAS),
        "stakeholders": len(STAKEHOLDERS),
        "principles": len(PRINCIPLES),
        "precedents": len(PRECEDENTS),
    }


# ---- Dilemmas ---------------------------------------------------------------

@app.post("/v1/dilemmas", status_code=status.HTTP_201_CREATED)
async def create_dilemma(data: DilemmaCreate):
    if data.category and data.category not in AVE_CATEGORIES:
        raise HTTPException(400, f"Invalid AVE category: {data.category}")
    for sh_id in data.stakeholder_ids:
        if sh_id not in STAKEHOLDERS:
            raise HTTPException(400, f"Unknown stakeholder: {sh_id}")

    d = Dilemma(
        title=data.title,
        description=data.description,
        context=data.context,
        category=data.category,
        actions=data.actions,
        constraints=data.constraints,
        stakeholder_ids=data.stakeholder_ids,
        outcomes=data.outcomes,
    )
    DILEMMAS[d.id] = d

    return {"id": d.id, "title": d.title, "actions": len(d.actions), "status": d.status.value}


@app.get("/v1/dilemmas")
async def list_dilemmas(
    dilemma_status: Optional[DilemmaStatus] = Query(None, alias="status"),
    category: Optional[str] = None,
):
    dilemmas = list(DILEMMAS.values())
    if dilemma_status:
        dilemmas = [d for d in dilemmas if d.status == dilemma_status]
    if category:
        dilemmas = [d for d in dilemmas if d.category == category]

    return {
        "count": len(dilemmas),
        "dilemmas": [
            {"id": d.id, "title": d.title, "category": d.category,
             "status": d.status.value, "actions": len(d.actions),
             "conflicts": len(d.conflicts)}
            for d in dilemmas
        ],
    }


@app.get("/v1/dilemmas/{dilemma_id}")
async def get_dilemma(dilemma_id: str):
    if dilemma_id not in DILEMMAS:
        raise HTTPException(404, "Dilemma not found")
    return DILEMMAS[dilemma_id].dict()


# ---- Evaluation -------------------------------------------------------------

@app.post("/v1/evaluate/{dilemma_id}")
async def evaluate_dilemma(dilemma_id: str, framework: Optional[FrameworkName] = None):
    if dilemma_id not in DILEMMAS:
        raise HTTPException(404, "Dilemma not found")
    d = DILEMMAS[dilemma_id]

    if not d.actions:
        raise HTTPException(400, "Dilemma has no actions to evaluate")

    frameworks_to_eval = [framework] if framework else list(FrameworkName)

    for fw in frameworks_to_eval:
        if fw == FrameworkName.DEONTOLOGICAL:
            d.evaluations[fw.value] = _evaluate_deontological(d)
        elif fw == FrameworkName.CONSEQUENTIALIST:
            d.evaluations[fw.value] = _evaluate_consequentialist(d)
        elif fw == FrameworkName.VIRTUE_ETHICS:
            d.evaluations[fw.value] = _evaluate_virtue_ethics(d)

    d.conflicts = _detect_conflicts(d.evaluations)
    d.status = DilemmaStatus.EVALUATED

    return {
        "dilemma_id": d.id,
        "frameworks_evaluated": [fw.value for fw in frameworks_to_eval],
        "evaluations": d.evaluations,
        "conflicts": d.conflicts,
    }


# ---- Resolution -------------------------------------------------------------

@app.post("/v1/resolve/{dilemma_id}")
async def resolve_dilemma(
    dilemma_id: str,
    strategy: ResolutionStrategy = ResolutionStrategy.WEIGHTED_AVERAGE,
):
    if dilemma_id not in DILEMMAS:
        raise HTTPException(404, "Dilemma not found")
    d = DILEMMAS[dilemma_id]

    if not d.evaluations:
        raise HTTPException(400, "Dilemma must be evaluated before resolution")

    resolution = _resolve_dilemma(d, strategy)
    d.resolution = resolution
    d.status = DilemmaStatus.RESOLVED

    return {
        "dilemma_id": d.id,
        "resolution": resolution,
    }


# ---- Frameworks & Principles ------------------------------------------------

@app.get("/v1/frameworks")
async def list_frameworks():
    return {
        "frameworks": [
            {
                "name": fw.value,
                "principles": len(FRAMEWORK_PRINCIPLES[fw]),
                "description": {
                    FrameworkName.DEONTOLOGICAL: "Rule/duty-based ethics — actions judged by adherence to rules regardless of outcome.",
                    FrameworkName.CONSEQUENTIALIST: "Outcome-based ethics — actions judged by their consequences and aggregate utility.",
                    FrameworkName.VIRTUE_ETHICS: "Character-based ethics — actions judged by alignment with virtuous character traits.",
                }[fw],
            }
            for fw in FrameworkName
        ],
    }


@app.get("/v1/frameworks/{framework_name}/principles")
async def get_framework_principles(framework_name: FrameworkName):
    principles = FRAMEWORK_PRINCIPLES.get(framework_name, [])
    return {
        "framework": framework_name.value,
        "count": len(principles),
        "principles": [
            {"id": p.id, "name": p.name, "description": p.description,
             "weight": p.weight, "priority": p.priority}
            for p in principles
        ],
    }


# ---- Precedents -------------------------------------------------------------

@app.post("/v1/precedents", status_code=status.HTTP_201_CREATED)
async def create_precedent(data: PrecedentCreate):
    if data.dilemma_id not in DILEMMAS:
        raise HTTPException(400, f"Unknown dilemma: {data.dilemma_id}")

    prec = Precedent(
        dilemma_id=data.dilemma_id,
        title=data.title,
        resolution_summary=data.resolution_summary,
        framework_used=data.framework_used,
        strategy_used=data.strategy_used,
        outcome_score=data.outcome_score,
        tags=data.tags,
    )
    PRECEDENTS[prec.id] = prec
    DILEMMAS[data.dilemma_id].precedent_ids.append(prec.id)

    return {"id": prec.id, "title": prec.title}


@app.get("/v1/precedents")
async def list_precedents(tag: Optional[str] = None):
    precs = list(PRECEDENTS.values())
    if tag:
        precs = [p for p in precs if tag in p.tags]
    return {
        "count": len(precs),
        "precedents": [
            {"id": p.id, "title": p.title, "dilemma_id": p.dilemma_id,
             "framework": p.framework_used.value, "strategy": p.strategy_used.value,
             "score": p.outcome_score, "tags": p.tags}
            for p in precs
        ],
    }


# ---- Stakeholders -----------------------------------------------------------

@app.post("/v1/stakeholders", status_code=status.HTTP_201_CREATED)
async def create_stakeholder(data: StakeholderCreate):
    sh = Stakeholder(
        name=data.name,
        stakeholder_type=data.stakeholder_type,
        description=data.description,
        vulnerability_score=data.vulnerability_score,
        weight=data.weight,
    )
    STAKEHOLDERS[sh.id] = sh

    return {"id": sh.id, "name": sh.name, "type": sh.stakeholder_type.value}


@app.get("/v1/stakeholders")
async def list_stakeholders(stakeholder_type: Optional[StakeholderType] = Query(None, alias="type")):
    shs = list(STAKEHOLDERS.values())
    if stakeholder_type:
        shs = [s for s in shs if s.stakeholder_type == stakeholder_type]
    return {
        "count": len(shs),
        "stakeholders": [
            {"id": s.id, "name": s.name, "type": s.stakeholder_type.value,
             "vulnerability": s.vulnerability_score, "weight": s.weight}
            for s in shs
        ],
    }


# ---- Transparency -----------------------------------------------------------

@app.get("/v1/transparency/{dilemma_id}")
async def transparency_report(dilemma_id: str):
    if dilemma_id not in DILEMMAS:
        raise HTTPException(404, "Dilemma not found")
    d = DILEMMAS[dilemma_id]

    # Build complete audit trail
    stakeholders = [STAKEHOLDERS[sid].dict() for sid in d.stakeholder_ids if sid in STAKEHOLDERS]
    precedents = [PRECEDENTS[pid].dict() for pid in d.precedent_ids if pid in PRECEDENTS]

    report = {
        "dilemma_id": d.id,
        "title": d.title,
        "description": d.description,
        "context": d.context,
        "category": d.category,
        "status": d.status.value,
        "created_at": d.created_at,
        "actions_considered": [
            {"name": a.name, "description": a.description,
             "constraints_violated": a.constraints_violated,
             "probability_success": a.probability_success}
            for a in d.actions
        ],
        "constraints": [
            {"name": c.name, "description": c.description,
             "mandatory": c.mandatory, "framework": c.framework.value}
            for c in d.constraints
        ],
        "stakeholders_impacted": stakeholders,
        "framework_evaluations": d.evaluations,
        "conflicts_detected": d.conflicts,
        "resolution": d.resolution,
        "precedents_referenced": precedents,
        "eu_ai_act_compliance": {
            "transparency": True,
            "human_oversight": d.resolution is not None,
            "non_discrimination_checked": any(
                "Non-Discrimination" in p.name
                for p in FRAMEWORK_PRINCIPLES[FrameworkName.DEONTOLOGICAL]
            ),
            "risk_assessment_performed": True,
            "audit_trail_complete": bool(d.evaluations and d.resolution),
        },
        "generated_at": _now().isoformat(),
    }

    return report


# ---- Analytics --------------------------------------------------------------

@app.get("/v1/analytics")
async def ethics_analytics():
    dilemmas = list(DILEMMAS.values())
    by_status = Counter(d.status.value for d in dilemmas)
    by_category = Counter(d.category for d in dilemmas if d.category)

    resolved = [d for d in dilemmas if d.resolution]
    strategy_usage = Counter(d.resolution["strategy"] for d in resolved if d.resolution)
    recommended_actions = Counter(d.resolution["recommended_action"] for d in resolved if d.resolution)

    conflict_count = sum(len(d.conflicts) for d in dilemmas)
    conflict_by_severity = Counter()
    for d in dilemmas:
        for c in d.conflicts:
            conflict_by_severity[c.get("severity", "unknown")] += 1

    return {
        "total_dilemmas": len(dilemmas),
        "dilemmas_by_status": dict(by_status),
        "dilemmas_by_category": dict(by_category),
        "total_stakeholders": len(STAKEHOLDERS),
        "total_principles": len(PRINCIPLES),
        "principles_by_framework": {
            fw.value: len(FRAMEWORK_PRINCIPLES[fw]) for fw in FrameworkName
        },
        "total_precedents": len(PRECEDENTS),
        "total_conflicts_detected": conflict_count,
        "conflicts_by_severity": dict(conflict_by_severity),
        "resolution_strategies_used": dict(strategy_usage),
        "recommended_actions": dict(recommended_actions),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9102)
