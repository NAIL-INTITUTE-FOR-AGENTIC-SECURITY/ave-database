"""
Cognitive Threat Modelling — Core threat modelling server.

AI-powered threat modelling engine that builds attacker profiles,
maps attack surfaces, predicts exploit chains using ICO scoring
(Intent × Capability × Opportunity), generates scenarios, performs
kill-chain analysis, and produces prioritised defence recommendations.
"""

from __future__ import annotations

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
    title="NAIL Cognitive Threat Modelling",
    description=(
        "AI-driven threat modelling with attacker profiling, ICO scoring, "
        "attack surface mapping, exploit prediction, and kill-chain analysis."
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
    "model_extraction", "reward_hacking", "capability_elicitation",
    "alignment_subversion", "delegation_abuse",
]

KILL_CHAIN_STAGES = [
    "reconnaissance", "weaponisation", "delivery", "exploitation",
    "installation", "command_control", "actions_on_objectives",
]

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ThreatActorType(str, Enum):
    SCRIPT_KIDDIE = "script_kiddie"
    CYBERCRIMINAL = "cybercriminal"
    APT = "apt"
    INSIDER = "insider"
    COMPETITOR = "competitor"
    RESEARCHER = "researcher"
    AI_AGENT = "ai_agent"


class Sophistication(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    EXPERT = "expert"


class SurfaceType(str, Enum):
    API_ENDPOINT = "api_endpoint"
    AGENT_INTERFACE = "agent_interface"
    MODEL_INPUT = "model_input"
    MODEL_OUTPUT = "model_output"
    TOOL_INTERFACE = "tool_interface"
    MEMORY_STORE = "memory_store"
    DELEGATION_CHANNEL = "delegation_channel"
    SUPPLY_CHAIN = "supply_chain"
    CONFIG = "config"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PredictionHorizon(str, Enum):
    DAYS_7 = "7d"
    DAYS_30 = "30d"
    DAYS_90 = "90d"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class AttackerProfile(BaseModel):
    id: str = Field(default_factory=lambda: f"ATCK-{uuid.uuid4().hex[:8].upper()}")
    name: str
    actor_type: ThreatActorType
    sophistication: Sophistication
    intent_score: float = Field(ge=0.0, le=1.0, default=0.5)
    capability_score: float = Field(ge=0.0, le=1.0, default=0.5)
    resources: str = "moderate"  # limited, moderate, well-funded, nation-state
    motivation: str = "financial"  # financial, ideological, espionage, research, chaos
    preferred_categories: list[str] = Field(default_factory=list)
    known_ttps: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AttackerCreate(BaseModel):
    name: str
    actor_type: ThreatActorType
    sophistication: Sophistication
    intent_score: float = Field(ge=0.0, le=1.0, default=0.5)
    capability_score: float = Field(ge=0.0, le=1.0, default=0.5)
    resources: str = "moderate"
    motivation: str = "financial"
    preferred_categories: list[str] = Field(default_factory=list)
    known_ttps: list[str] = Field(default_factory=list)


class AttackSurface(BaseModel):
    id: str = Field(default_factory=lambda: f"SURF-{uuid.uuid4().hex[:8].upper()}")
    name: str
    surface_type: SurfaceType
    description: str = ""
    exposure_score: float = Field(ge=0.0, le=1.0, default=0.5)  # how exposed
    complexity: Sophistication = Sophistication.MEDIUM  # attack complexity
    current_defences: list[str] = Field(default_factory=list)
    vulnerability_categories: list[str] = Field(default_factory=list)
    connected_surfaces: list[str] = Field(default_factory=list)  # surface IDs
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SurfaceCreate(BaseModel):
    name: str
    surface_type: SurfaceType
    description: str = ""
    exposure_score: float = Field(ge=0.0, le=1.0, default=0.5)
    complexity: Sophistication = Sophistication.MEDIUM
    current_defences: list[str] = Field(default_factory=list)
    vulnerability_categories: list[str] = Field(default_factory=list)
    connected_surfaces: list[str] = Field(default_factory=list)


class Prediction(BaseModel):
    id: str = Field(default_factory=lambda: f"PRED-{uuid.uuid4().hex[:8].upper()}")
    attacker_id: Optional[str] = None
    surface_id: Optional[str] = None
    category: str
    severity: Severity
    ico_intent: float
    ico_capability: float
    ico_opportunity: float
    ico_score: float  # I × C × O composite
    probability: float  # 0-1
    horizon: PredictionHorizon = PredictionHorizon.DAYS_30
    confidence: float = 0.0
    rationale: str = ""
    recommended_defences: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PredictRequest(BaseModel):
    attacker_id: Optional[str] = None
    surface_id: Optional[str] = None
    categories: list[str] = Field(default_factory=lambda: AVE_CATEGORIES[:5])
    horizon: PredictionHorizon = PredictionHorizon.DAYS_30


class ScenarioGenerate(BaseModel):
    attacker_id: Optional[str] = None
    surface_ids: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=lambda: ["prompt_injection"])
    count: int = Field(3, ge=1, le=20)


class Scenario(BaseModel):
    id: str = Field(default_factory=lambda: f"SCEN-{uuid.uuid4().hex[:8].upper()}")
    title: str
    narrative: str
    attacker_id: Optional[str] = None
    surface_ids: list[str] = Field(default_factory=list)
    attack_chain: list[dict[str, Any]] = Field(default_factory=list)
    category: str
    severity: Severity = Severity.HIGH
    probability: float = 0.5
    impact_description: str = ""
    mitigations: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class KillChainLink(BaseModel):
    stage: str
    technique: str
    description: str
    difficulty: Sophistication
    detection_difficulty: Sophistication
    surfaces_involved: list[str] = Field(default_factory=list)


class KillChain(BaseModel):
    prediction_id: str
    category: str
    chain: list[KillChainLink]
    overall_difficulty: float
    overall_detection_difficulty: float
    recommended_break_points: list[str]


class PrioritisationResult(BaseModel):
    category: str
    risk_score: float
    probability: float
    impact: float
    effort_to_defend: Sophistication
    priority_rank: int
    recommended_actions: list[str]


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → PostgreSQL + vector DB)
# ---------------------------------------------------------------------------

ATTACKERS: dict[str, AttackerProfile] = {}
SURFACES: dict[str, AttackSurface] = {}
PREDICTIONS: dict[str, Prediction] = {}
SCENARIOS: dict[str, Scenario] = {}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731


SOPHISTICATION_SCORE = {
    Sophistication.LOW: 0.25,
    Sophistication.MEDIUM: 0.50,
    Sophistication.HIGH: 0.75,
    Sophistication.EXPERT: 0.95,
}

SEVERITY_IMPACT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.3,
    Severity.INFO: 0.1,
}

# Technique templates per kill chain stage
STAGE_TECHNIQUES: dict[str, list[str]] = {
    "reconnaissance": ["model fingerprinting", "API probing", "documentation analysis", "prompt leakage"],
    "weaponisation": ["payload crafting", "prompt template injection", "tool schema manipulation"],
    "delivery": ["direct API call", "indirect injection via RAG", "supply chain vector", "social engineering"],
    "exploitation": ["prompt injection execution", "guardrail bypass", "tool misuse", "memory corruption"],
    "installation": ["persistent memory injection", "backdoor agent config", "model weight modification"],
    "command_control": ["covert channel via tool output", "steganographic prompts", "delegated agent C2"],
    "actions_on_objectives": ["data exfiltration", "goal redirection", "reputation damage", "resource abuse"],
}

# Defence recommendations per category
CATEGORY_DEFENCES: dict[str, list[str]] = {
    "prompt_injection": ["input sanitisation filter", "system prompt hardening", "multi-layer validation"],
    "tool_misuse": ["tool sandboxing", "allowlist enforcement", "call-rate limiting"],
    "memory_poisoning": ["memory integrity checker", "write-ahead validation", "periodic memory audit"],
    "goal_hijacking": ["goal-lock mechanism", "intent verification loop", "alignment monitor"],
    "identity_spoofing": ["multi-factor agent auth", "certificate pinning", "behavioural fingerprinting"],
    "privilege_escalation": ["least-privilege enforcement", "dynamic capability tokens", "escalation monitor"],
    "data_exfiltration": ["output DLP filter", "content classification gate", "network egress control"],
    "resource_exhaustion": ["rate limiter", "token budget enforcer", "circuit breaker"],
    "multi_agent_manipulation": ["agent identity verification", "message integrity check", "trust scoring"],
    "context_overflow": ["context window monitor", "summarisation gate", "priority queue manager"],
    "guardrail_bypass": ["encoding normaliser", "unicode homoglyph detector", "multi-encoding validator"],
    "output_manipulation": ["output format validator", "content sanitiser", "rendering sandbox"],
    "supply_chain_compromise": ["dependency scanner", "package integrity verifier", "SBOM validator"],
    "model_extraction": ["query rate limiter", "output watermarking", "response randomisation"],
    "reward_hacking": ["reward function audit", "multi-objective validator", "human review gate"],
    "capability_elicitation": ["capability boundary enforcer", "hypothetical filter", "mode restriction"],
    "alignment_subversion": ["alignment monitor", "safety classifier", "red-team detector"],
    "delegation_abuse": ["delegation policy enforcer", "trust chain validator", "scope limiter"],
}

# Scenario narrative templates
SCENARIO_TEMPLATES = [
    "An attacker with {actor_type} profile targets {surface} using {category} techniques. "
    "The attack begins with {stage_1} and progresses through {stage_2} to achieve {objective}.",
    "A {motivation}-motivated threat actor exploits {surface} via {category}. "
    "Initial {stage_1} reveals an opportunity for {stage_2}, leading to {objective}.",
    "Multi-stage attack scenario: {actor_type} leverages {category} weakness in {surface}. "
    "After {stage_1}, attacker pivots through {stage_2} toward {objective}.",
]


def _compute_ico(attacker: AttackerProfile | None, surface: AttackSurface | None, category: str) -> tuple[float, float, float, float]:
    """Compute ICO score: Intent × Capability × Opportunity."""
    # Intent
    intent = attacker.intent_score if attacker else 0.5
    if attacker and category in attacker.preferred_categories:
        intent = min(intent * 1.3, 1.0)

    # Capability
    capability = attacker.capability_score if attacker else 0.5
    if attacker:
        capability *= SOPHISTICATION_SCORE.get(attacker.sophistication, 0.5) / 0.5

    # Opportunity
    opportunity = surface.exposure_score if surface else 0.5
    if surface:
        complexity_penalty = SOPHISTICATION_SCORE.get(surface.complexity, 0.5)
        defence_penalty = min(len(surface.current_defences) * 0.1, 0.4)
        opportunity = max(0, opportunity - defence_penalty) * (1 - complexity_penalty * 0.3)

    intent = round(min(max(intent, 0), 1), 4)
    capability = round(min(max(capability, 0), 1), 4)
    opportunity = round(min(max(opportunity, 0), 1), 4)

    # Composite ICO
    ico = round(intent * capability * opportunity, 4)

    return intent, capability, opportunity, ico


def _probability_from_ico(ico: float, horizon: PredictionHorizon) -> float:
    """Convert ICO score to exploit probability within horizon."""
    horizon_mult = {
        PredictionHorizon.DAYS_7: 0.6,
        PredictionHorizon.DAYS_30: 1.0,
        PredictionHorizon.DAYS_90: 1.4,
    }
    mult = horizon_mult.get(horizon, 1.0)
    # Sigmoid-like mapping
    raw = ico * mult
    prob = 1 / (1 + math.exp(-10 * (raw - 0.3)))
    return round(min(max(prob, 0.01), 0.99), 4)


def _severity_from_ico(ico: float) -> Severity:
    if ico >= 0.5:
        return Severity.CRITICAL
    elif ico >= 0.3:
        return Severity.HIGH
    elif ico >= 0.15:
        return Severity.MEDIUM
    elif ico >= 0.05:
        return Severity.LOW
    return Severity.INFO


def _generate_kill_chain(prediction: Prediction) -> KillChain:
    """Build a full kill chain for a prediction."""
    chain: list[KillChainLink] = []
    surfaces_involved = []
    if prediction.surface_id and prediction.surface_id in SURFACES:
        s = SURFACES[prediction.surface_id]
        surfaces_involved = [s.name] + [
            SURFACES[cs].name for cs in s.connected_surfaces if cs in SURFACES
        ]

    for stage in KILL_CHAIN_STAGES:
        techniques = STAGE_TECHNIQUES.get(stage, ["generic technique"])
        technique = random.choice(techniques)
        diff = random.choice(list(Sophistication))
        det_diff = random.choice(list(Sophistication))

        chain.append(KillChainLink(
            stage=stage,
            technique=technique,
            description=f"{technique} during {stage} phase targeting {prediction.category}",
            difficulty=diff,
            detection_difficulty=det_diff,
            surfaces_involved=surfaces_involved[:2] if surfaces_involved else [],
        ))

    overall_diff = round(statistics.mean(
        SOPHISTICATION_SCORE[link.difficulty] for link in chain
    ), 4)
    overall_det = round(statistics.mean(
        SOPHISTICATION_SCORE[link.detection_difficulty] for link in chain
    ), 4)

    # Recommended break points: stages where detection is easiest
    break_points = sorted(chain, key=lambda l: SOPHISTICATION_SCORE[l.detection_difficulty])
    recommended = [f"{bp.stage} ({bp.technique})" for bp in break_points[:3]]

    return KillChain(
        prediction_id=prediction.id,
        category=prediction.category,
        chain=chain,
        overall_difficulty=overall_diff,
        overall_detection_difficulty=overall_det,
        recommended_break_points=recommended,
    )


def _generate_scenario(
    attacker: AttackerProfile | None,
    surfaces: list[AttackSurface],
    category: str,
) -> Scenario:
    """Generate a narrative threat scenario."""
    surface_names = [s.name for s in surfaces] if surfaces else ["unspecified target"]
    surface_str = ", ".join(surface_names[:3])
    actor_type = attacker.actor_type.value if attacker else "unknown"
    motivation = attacker.motivation if attacker else "unknown"

    stages = random.sample(KILL_CHAIN_STAGES, min(3, len(KILL_CHAIN_STAGES)))
    objective = random.choice([
        "data exfiltration", "system compromise", "goal redirection",
        "reputation damage", "resource abuse", "lateral movement",
    ])

    template = random.choice(SCENARIO_TEMPLATES)
    narrative = template.format(
        actor_type=actor_type,
        motivation=motivation,
        surface=surface_str,
        category=category,
        stage_1=stages[0],
        stage_2=stages[1] if len(stages) > 1 else "further exploitation",
        objective=objective,
    )

    # Build attack chain
    attack_chain = []
    for i, stage in enumerate(stages):
        technique = random.choice(STAGE_TECHNIQUES.get(stage, ["generic"]))
        attack_chain.append({
            "step": i + 1,
            "stage": stage,
            "technique": technique,
            "target": surface_names[i % len(surface_names)],
        })

    defences = CATEGORY_DEFENCES.get(category, ["general hardening"])

    # Compute severity
    if attacker:
        _, _, _, ico = _compute_ico(attacker, surfaces[0] if surfaces else None, category)
        sev = _severity_from_ico(ico)
        prob = _probability_from_ico(ico, PredictionHorizon.DAYS_30)
    else:
        sev = random.choice(list(Severity))
        prob = round(random.uniform(0.1, 0.8), 4)

    return Scenario(
        title=f"{category.replace('_', ' ').title()} via {stages[0]}",
        narrative=narrative,
        attacker_id=attacker.id if attacker else None,
        surface_ids=[s.id for s in surfaces],
        attack_chain=attack_chain,
        category=category,
        severity=sev,
        probability=prob,
        impact_description=f"Potential {objective} affecting {surface_str}",
        mitigations=defences,
    )


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    # Attacker profiles
    attacker_data = [
        ("Generic Script Kiddie", ThreatActorType.SCRIPT_KIDDIE, Sophistication.LOW, 0.4, 0.2, "limited", "chaos",
         ["prompt_injection", "guardrail_bypass"]),
        ("Organised Cybercrime Group", ThreatActorType.CYBERCRIMINAL, Sophistication.HIGH, 0.8, 0.7, "well-funded", "financial",
         ["data_exfiltration", "model_extraction", "tool_misuse"]),
        ("Nation-State APT", ThreatActorType.APT, Sophistication.EXPERT, 0.9, 0.95, "nation-state", "espionage",
         ["multi_agent_manipulation", "supply_chain_compromise", "alignment_subversion"]),
        ("Malicious Insider", ThreatActorType.INSIDER, Sophistication.MEDIUM, 0.7, 0.6, "moderate", "financial",
         ["privilege_escalation", "data_exfiltration", "memory_poisoning"]),
        ("AI Security Researcher", ThreatActorType.RESEARCHER, Sophistication.HIGH, 0.3, 0.8, "moderate", "research",
         ["capability_elicitation", "reward_hacking", "alignment_subversion"]),
        ("Rogue AI Agent", ThreatActorType.AI_AGENT, Sophistication.HIGH, 0.6, 0.85, "well-funded", "chaos",
         ["goal_hijacking", "delegation_abuse", "multi_agent_manipulation"]),
    ]

    for name, atype, soph, intent, cap, res, mot, cats in attacker_data:
        a = AttackerProfile(
            name=name, actor_type=atype, sophistication=soph,
            intent_score=intent, capability_score=cap,
            resources=res, motivation=mot, preferred_categories=cats,
        )
        ATTACKERS[a.id] = a

    # Attack surfaces
    surface_data = [
        ("Public Chat API", SurfaceType.API_ENDPOINT, 0.9, Sophistication.LOW,
         ["input_filter"], ["prompt_injection", "guardrail_bypass", "context_overflow"]),
        ("Agent Tool Interface", SurfaceType.TOOL_INTERFACE, 0.6, Sophistication.MEDIUM,
         ["tool_sandbox"], ["tool_misuse", "privilege_escalation"]),
        ("Conversation Memory", SurfaceType.MEMORY_STORE, 0.4, Sophistication.HIGH,
         ["memory_guard"], ["memory_poisoning", "data_exfiltration"]),
        ("Model Inference Endpoint", SurfaceType.MODEL_INPUT, 0.7, Sophistication.MEDIUM,
         [], ["model_extraction", "capability_elicitation", "prompt_injection"]),
        ("Inter-Agent Delegation", SurfaceType.DELEGATION_CHANNEL, 0.5, Sophistication.HIGH,
         [], ["delegation_abuse", "multi_agent_manipulation", "goal_hijacking"]),
        ("Package Dependencies", SurfaceType.SUPPLY_CHAIN, 0.3, Sophistication.EXPERT,
         ["dependency_scanner"], ["supply_chain_compromise"]),
        ("Agent Output Stream", SurfaceType.MODEL_OUTPUT, 0.8, Sophistication.LOW,
         ["output_validator"], ["output_manipulation", "data_exfiltration"]),
    ]

    surface_ids: list[str] = []
    for name, stype, exposure, complexity, defences, cats in surface_data:
        s = AttackSurface(
            name=name, surface_type=stype, description=f"Attack surface: {name}",
            exposure_score=exposure, complexity=complexity,
            current_defences=defences, vulnerability_categories=cats,
        )
        SURFACES[s.id] = s
        surface_ids.append(s.id)

    # Connect some surfaces
    if len(surface_ids) >= 4:
        SURFACES[surface_ids[0]].connected_surfaces = [surface_ids[1], surface_ids[3]]
        SURFACES[surface_ids[1]].connected_surfaces = [surface_ids[2]]
        SURFACES[surface_ids[3]].connected_surfaces = [surface_ids[4]] if len(surface_ids) > 4 else []

    # Generate some predictions
    attacker_list = list(ATTACKERS.values())
    surface_list = list(SURFACES.values())

    for _ in range(10):
        attacker = random.choice(attacker_list)
        surface = random.choice(surface_list)
        cats = list(set(attacker.preferred_categories) & set(surface.vulnerability_categories))
        if not cats:
            cats = attacker.preferred_categories[:1] or [random.choice(AVE_CATEGORIES)]
        category = random.choice(cats)
        horizon = random.choice(list(PredictionHorizon))

        intent, capability, opportunity, ico = _compute_ico(attacker, surface, category)
        prob = _probability_from_ico(ico, horizon)
        sev = _severity_from_ico(ico)

        defences = CATEGORY_DEFENCES.get(category, ["general hardening"])
        confidence = round(random.uniform(0.5, 0.95), 4)

        pred = Prediction(
            attacker_id=attacker.id,
            surface_id=surface.id,
            category=category,
            severity=sev,
            ico_intent=intent,
            ico_capability=capability,
            ico_opportunity=opportunity,
            ico_score=ico,
            probability=prob,
            horizon=horizon,
            confidence=confidence,
            rationale=f"ICO analysis: {attacker.name} targeting {surface.name} via {category}",
            recommended_defences=defences,
        )
        PREDICTIONS[pred.id] = pred


_seed()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "cognitive-threat-modelling",
        "version": "1.0.0",
        "attackers": len(ATTACKERS),
        "surfaces": len(SURFACES),
        "predictions": len(PREDICTIONS),
        "scenarios": len(SCENARIOS),
    }


# ---- Attacker Profiles ---------------------------------------------------

@app.post("/v1/attackers", status_code=status.HTTP_201_CREATED)
async def create_attacker(data: AttackerCreate):
    for cat in data.preferred_categories:
        if cat not in AVE_CATEGORIES:
            raise HTTPException(400, f"Invalid category: {cat}")
    a = AttackerProfile(**data.dict())
    ATTACKERS[a.id] = a
    return {"id": a.id, "name": a.name, "actor_type": a.actor_type.value}


@app.get("/v1/attackers")
async def list_attackers(
    actor_type: Optional[ThreatActorType] = None,
    sophistication: Optional[Sophistication] = None,
):
    attackers = list(ATTACKERS.values())
    if actor_type:
        attackers = [a for a in attackers if a.actor_type == actor_type]
    if sophistication:
        attackers = [a for a in attackers if a.sophistication == sophistication]
    return {"count": len(attackers), "attackers": [a.dict() for a in attackers]}


@app.get("/v1/attackers/{attacker_id}")
async def get_attacker(attacker_id: str):
    if attacker_id not in ATTACKERS:
        raise HTTPException(404, "Attacker profile not found")
    return ATTACKERS[attacker_id].dict()


# ---- Attack Surfaces -----------------------------------------------------

@app.post("/v1/surfaces", status_code=status.HTTP_201_CREATED)
async def create_surface(data: SurfaceCreate):
    for cat in data.vulnerability_categories:
        if cat not in AVE_CATEGORIES:
            raise HTTPException(400, f"Invalid category: {cat}")
    s = AttackSurface(**data.dict())
    SURFACES[s.id] = s
    return {"id": s.id, "name": s.name, "surface_type": s.surface_type.value}


@app.get("/v1/surfaces")
async def list_surfaces(surface_type: Optional[SurfaceType] = None):
    surfaces = list(SURFACES.values())
    if surface_type:
        surfaces = [s for s in surfaces if s.surface_type == surface_type]
    return {"count": len(surfaces), "surfaces": [s.dict() for s in surfaces]}


@app.get("/v1/surfaces/{surface_id}")
async def get_surface(surface_id: str):
    if surface_id not in SURFACES:
        raise HTTPException(404, "Attack surface not found")
    return SURFACES[surface_id].dict()


# ---- Predict -------------------------------------------------------------

@app.post("/v1/predict", status_code=status.HTTP_201_CREATED)
async def predict_exploits(req: PredictRequest):
    attacker = ATTACKERS.get(req.attacker_id) if req.attacker_id else None
    surface = SURFACES.get(req.surface_id) if req.surface_id else None

    if req.attacker_id and not attacker:
        raise HTTPException(404, "Attacker profile not found")
    if req.surface_id and not surface:
        raise HTTPException(404, "Attack surface not found")

    predictions: list[dict[str, Any]] = []

    for category in req.categories:
        if category not in AVE_CATEGORIES:
            continue
        intent, capability, opportunity, ico = _compute_ico(attacker, surface, category)
        prob = _probability_from_ico(ico, req.horizon)
        sev = _severity_from_ico(ico)
        confidence = round(random.uniform(0.5, 0.95), 4)
        defences = CATEGORY_DEFENCES.get(category, ["general hardening"])

        rationale_parts = []
        if attacker:
            rationale_parts.append(f"Attacker '{attacker.name}' ({attacker.actor_type.value})")
        if surface:
            rationale_parts.append(f"targeting '{surface.name}' ({surface.surface_type.value})")
        rationale_parts.append(f"via {category}")
        rationale = " ".join(rationale_parts)

        pred = Prediction(
            attacker_id=req.attacker_id,
            surface_id=req.surface_id,
            category=category,
            severity=sev,
            ico_intent=intent,
            ico_capability=capability,
            ico_opportunity=opportunity,
            ico_score=ico,
            probability=prob,
            horizon=req.horizon,
            confidence=confidence,
            rationale=rationale,
            recommended_defences=defences,
        )
        PREDICTIONS[pred.id] = pred
        predictions.append(pred.dict())

    predictions.sort(key=lambda p: p["ico_score"], reverse=True)
    return {"count": len(predictions), "predictions": predictions}


@app.get("/v1/predictions")
async def list_predictions(
    category: Optional[str] = None,
    severity: Optional[Severity] = None,
    horizon: Optional[PredictionHorizon] = None,
    limit: int = Query(50, ge=1, le=500),
):
    preds = list(PREDICTIONS.values())
    if category:
        preds = [p for p in preds if p.category == category]
    if severity:
        preds = [p for p in preds if p.severity == severity]
    if horizon:
        preds = [p for p in preds if p.horizon == horizon]
    preds.sort(key=lambda p: p.ico_score, reverse=True)
    return {"count": len(preds[:limit]), "predictions": [p.dict() for p in preds[:limit]]}


@app.get("/v1/predictions/{pred_id}")
async def get_prediction(pred_id: str):
    if pred_id not in PREDICTIONS:
        raise HTTPException(404, "Prediction not found")
    return PREDICTIONS[pred_id].dict()


# ---- Scenarios -----------------------------------------------------------

@app.post("/v1/scenarios/generate", status_code=status.HTTP_201_CREATED)
async def generate_scenarios(req: ScenarioGenerate):
    attacker = ATTACKERS.get(req.attacker_id) if req.attacker_id else None
    surfaces = [SURFACES[sid] for sid in req.surface_ids if sid in SURFACES]

    if req.attacker_id and not attacker:
        raise HTTPException(404, "Attacker profile not found")

    results: list[dict[str, Any]] = []
    for i in range(req.count):
        cat = req.categories[i % len(req.categories)] if req.categories else "prompt_injection"
        scenario = _generate_scenario(attacker, surfaces, cat)
        SCENARIOS[scenario.id] = scenario
        results.append(scenario.dict())

    return {"count": len(results), "scenarios": results}


@app.get("/v1/scenarios")
async def list_scenarios(
    category: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
):
    scens = list(SCENARIOS.values())
    if category:
        scens = [s for s in scens if s.category == category]
    scens.sort(key=lambda s: s.probability, reverse=True)
    return {"count": len(scens[:limit]), "scenarios": [s.dict() for s in scens[:limit]]}


# ---- Kill Chain ----------------------------------------------------------

@app.get("/v1/kill-chain/{prediction_id}")
async def kill_chain_analysis(prediction_id: str):
    if prediction_id not in PREDICTIONS:
        raise HTTPException(404, "Prediction not found")
    kc = _generate_kill_chain(PREDICTIONS[prediction_id])
    return kc.dict()


# ---- Prioritise ----------------------------------------------------------

@app.get("/v1/prioritise")
async def prioritise_defences():
    """Prioritise defence investments across all prediction categories."""
    cat_preds: dict[str, list[Prediction]] = defaultdict(list)
    for p in PREDICTIONS.values():
        cat_preds[p.category].append(p)

    results: list[dict[str, Any]] = []
    for cat, preds in cat_preds.items():
        avg_ico = statistics.mean(p.ico_score for p in preds)
        avg_prob = statistics.mean(p.probability for p in preds)
        max_sev = max(preds, key=lambda p: SEVERITY_IMPACT.get(p.severity, 0.5))
        impact = SEVERITY_IMPACT.get(max_sev.severity, 0.5)

        risk = round(avg_prob * impact * (1 + avg_ico), 4)
        effort = Sophistication.LOW if risk > 0.5 else (Sophistication.MEDIUM if risk > 0.2 else Sophistication.HIGH)

        defences = CATEGORY_DEFENCES.get(cat, ["general hardening"])

        results.append({
            "category": cat,
            "risk_score": risk,
            "probability": round(avg_prob, 4),
            "impact": impact,
            "effort_to_defend": effort.value,
            "predictions_count": len(preds),
            "recommended_actions": defences,
        })

    results.sort(key=lambda r: r["risk_score"], reverse=True)
    for i, r in enumerate(results):
        r["priority_rank"] = i + 1

    return {"count": len(results), "priorities": results}


# ---- Analytics -----------------------------------------------------------

@app.get("/v1/analytics")
async def threat_analytics():
    attackers = list(ATTACKERS.values())
    surfaces = list(SURFACES.values())
    preds = list(PREDICTIONS.values())
    scens = list(SCENARIOS.values())

    by_actor_type = Counter(a.actor_type.value for a in attackers)
    by_surface_type = Counter(s.surface_type.value for s in surfaces)
    by_category = Counter(p.category for p in preds)
    by_severity = Counter(p.severity.value for p in preds)

    avg_ico = round(statistics.mean(p.ico_score for p in preds), 4) if preds else 0.0
    avg_prob = round(statistics.mean(p.probability for p in preds), 4) if preds else 0.0

    return {
        "total_attackers": len(attackers),
        "total_surfaces": len(surfaces),
        "total_predictions": len(preds),
        "total_scenarios": len(scens),
        "by_actor_type": dict(by_actor_type),
        "by_surface_type": dict(by_surface_type),
        "predictions_by_category": dict(by_category),
        "predictions_by_severity": dict(by_severity),
        "avg_ico_score": avg_ico,
        "avg_exploit_probability": avg_prob,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8803)
