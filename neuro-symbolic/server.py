"""
Neuro-Symbolic Threat Reasoning — Core reasoning server.

Hybrid neuro-symbolic engine combining neural pattern recognition
with formal logic-based threat reasoning.  Neural modules score
raw signals, symbolic modules construct formally-verifiable causal
chains, counterfactual simulator tests "what-if" scenarios, and
explanation generator produces human-readable justifications.
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
    title="NAIL Neuro-Symbolic Threat Reasoning",
    description=(
        "Hybrid neuro-symbolic engine — neural pattern detection + "
        "formal logic reasoning + counterfactual simulation."
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


class FactStatus(str, Enum):
    ACTIVE = "active"
    RETRACTED = "retracted"


class RulePriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConclusionConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CERTAIN = "certain"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class Fact(BaseModel):
    id: str = Field(default_factory=lambda: f"FACT-{uuid.uuid4().hex[:8].upper()}")
    predicate: str  # e.g., "is_threat", "has_vulnerability", "targets"
    subject: str  # Entity name
    object: str = ""  # Optional second entity
    category: str = ""  # AVE category
    confidence: float = Field(ge=0.0, le=1.0, default=0.9)
    source: str = "manual"  # manual | neural | inferred
    status: FactStatus = FactStatus.ACTIVE
    metadata: dict[str, Any] = Field(default_factory=dict)
    asserted_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FactCreate(BaseModel):
    predicate: str
    subject: str
    object: str = ""
    category: str = ""
    confidence: float = Field(ge=0.0, le=1.0, default=0.9)
    source: str = "manual"
    metadata: dict[str, Any] = Field(default_factory=dict)


class SymbolicRule(BaseModel):
    id: str = Field(default_factory=lambda: f"RULE-{uuid.uuid4().hex[:8].upper()}")
    name: str
    description: str = ""
    category: str = ""
    priority: RulePriority = RulePriority.MEDIUM
    antecedents: list[dict[str, str]] = Field(default_factory=list)  # [{predicate, subject?, object?}]
    consequent: dict[str, str] = Field(default_factory=dict)  # {predicate, subject, object}
    confidence_factor: float = Field(ge=0.0, le=1.0, default=0.85)
    enabled: bool = True
    fire_count: int = 0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RuleCreate(BaseModel):
    name: str
    description: str = ""
    category: str = ""
    priority: RulePriority = RulePriority.MEDIUM
    antecedents: list[dict[str, str]] = Field(default_factory=list)
    consequent: dict[str, str] = Field(default_factory=dict)
    confidence_factor: float = Field(ge=0.0, le=1.0, default=0.85)


class Conclusion(BaseModel):
    id: str = Field(default_factory=lambda: f"CONC-{uuid.uuid4().hex[:8].upper()}")
    predicate: str
    subject: str
    object: str = ""
    category: str = ""
    confidence: float = 0.0
    confidence_level: ConclusionConfidence = ConclusionConfidence.MEDIUM
    derivation_chain: list[str] = Field(default_factory=list)  # Rule IDs
    supporting_facts: list[str] = Field(default_factory=list)  # Fact IDs
    depth: int = 0
    derived_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class NeuralSignal(BaseModel):
    id: str = Field(default_factory=lambda: f"SIG-{uuid.uuid4().hex[:8].upper()}")
    raw_text: str
    embedding: list[float] = Field(default_factory=list)
    patterns_detected: list[dict[str, Any]] = Field(default_factory=list)
    anomaly_score: float = 0.0
    encoded_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FusionResult(BaseModel):
    id: str = Field(default_factory=lambda: f"FUS-{uuid.uuid4().hex[:8].upper()}")
    neural_confidence: float = 0.0
    symbolic_confidence: float = 0.0
    fused_confidence: float = 0.0
    category: str = ""
    explanation: str = ""
    neural_patterns: list[dict[str, Any]] = Field(default_factory=list)
    symbolic_conclusions: list[str] = Field(default_factory=list)
    fused_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → Neo4j + PostgreSQL + FAISS)
# ---------------------------------------------------------------------------

FACTS: dict[str, Fact] = {}
RULES: dict[str, SymbolicRule] = {}
CONCLUSIONS: dict[str, Conclusion] = {}
NEURAL_SIGNALS: dict[str, NeuralSignal] = {}
FUSION_RESULTS: dict[str, FusionResult] = {}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731


def _match_antecedent(ant: dict[str, str], facts: list[Fact]) -> list[Fact]:
    """Find facts matching an antecedent pattern."""
    matches = []
    for f in facts:
        if f.status != FactStatus.ACTIVE:
            continue
        if ant.get("predicate") and ant["predicate"] != f.predicate:
            continue
        if ant.get("subject") and ant["subject"] != f.subject:
            continue
        if ant.get("object") and ant["object"] != f.object:
            continue
        matches.append(f)
    return matches


def _forward_chain(max_depth: int = 5) -> list[Conclusion]:
    """Run forward-chaining inference over the knowledge base."""
    active_facts = [f for f in FACTS.values() if f.status == FactStatus.ACTIVE]
    new_conclusions: list[Conclusion] = []
    seen_keys: set[str] = set()

    # Track already-derived conclusions to avoid duplicates
    for c in CONCLUSIONS.values():
        seen_keys.add(f"{c.predicate}:{c.subject}:{c.object}")

    for depth in range(max_depth):
        fired_any = False

        for rule in RULES.values():
            if not rule.enabled:
                continue

            # Check all antecedents are satisfied
            all_matched = True
            matched_facts: list[Fact] = []
            for ant in rule.antecedents:
                matches = _match_antecedent(ant, active_facts)
                if not matches:
                    all_matched = False
                    break
                matched_facts.extend(matches)

            if not all_matched:
                continue

            # Construct consequent
            cons = rule.consequent
            key = f"{cons.get('predicate', '')}:{cons.get('subject', '')}:{cons.get('object', '')}"
            if key in seen_keys:
                continue

            # Calculate confidence: product of matched fact confidences × rule confidence factor
            fact_conf = min(f.confidence for f in matched_facts) if matched_facts else 0.5
            combined_conf = round(fact_conf * rule.confidence_factor, 4)

            # Classify confidence level
            if combined_conf >= 0.9:
                conf_level = ConclusionConfidence.CERTAIN
            elif combined_conf >= 0.7:
                conf_level = ConclusionConfidence.HIGH
            elif combined_conf >= 0.4:
                conf_level = ConclusionConfidence.MEDIUM
            else:
                conf_level = ConclusionConfidence.LOW

            conclusion = Conclusion(
                predicate=cons.get("predicate", "unknown"),
                subject=cons.get("subject", "unknown"),
                object=cons.get("object", ""),
                category=rule.category,
                confidence=combined_conf,
                confidence_level=conf_level,
                derivation_chain=[rule.id],
                supporting_facts=[f.id for f in matched_facts],
                depth=depth,
            )

            CONCLUSIONS[conclusion.id] = conclusion
            new_conclusions.append(conclusion)
            seen_keys.add(key)
            rule.fire_count += 1
            fired_any = True

            # Add derived conclusion as a new fact for chaining
            derived_fact = Fact(
                predicate=conclusion.predicate,
                subject=conclusion.subject,
                object=conclusion.object,
                category=conclusion.category,
                confidence=conclusion.confidence,
                source="inferred",
                metadata={"conclusion_id": conclusion.id},
            )
            FACTS[derived_fact.id] = derived_fact
            active_facts.append(derived_fact)

        if not fired_any:
            break

    return new_conclusions


def _explain(conclusion: Conclusion) -> str:
    """Generate human-readable explanation for a conclusion."""
    parts: list[str] = []
    parts.append(f"CONCLUSION: {conclusion.predicate}({conclusion.subject}"
                 f"{', ' + conclusion.object if conclusion.object else ''}) "
                 f"[confidence: {conclusion.confidence:.2%}]")
    parts.append("")

    parts.append("REASONING CHAIN:")
    for i, rule_id in enumerate(conclusion.derivation_chain):
        rule = RULES.get(rule_id)
        if rule:
            parts.append(f"  Step {i + 1}: Applied rule '{rule.name}' (priority: {rule.priority.value})")
            ants = " AND ".join(
                f"{a.get('predicate', '?')}({a.get('subject', '?')}"
                f"{', ' + a.get('object', '') if a.get('object') else ''})"
                for a in rule.antecedents
            )
            cons = f"{rule.consequent.get('predicate', '?')}({rule.consequent.get('subject', '?')}" \
                   f"{', ' + rule.consequent.get('object', '') if rule.consequent.get('object') else ''})"
            parts.append(f"           IF {ants} THEN {cons}")

    parts.append("")
    parts.append("SUPPORTING EVIDENCE:")
    for fid in conclusion.supporting_facts:
        fact = FACTS.get(fid)
        if fact:
            parts.append(f"  - {fact.predicate}({fact.subject}"
                         f"{', ' + fact.object if fact.object else ''}) "
                         f"[source: {fact.source}, confidence: {fact.confidence:.2%}]")

    parts.append("")
    parts.append(f"OVERALL ASSESSMENT: {conclusion.confidence_level.value.upper()} confidence "
                 f"({conclusion.confidence:.2%}) derived at depth {conclusion.depth}")

    return "\n".join(parts)


def _sim_neural_encode(text: str) -> list[float]:
    """Simulate neural encoding (production → sentence-transformers)."""
    # Deterministic pseudo-embedding from text hash
    h = hashlib.sha256(text.encode()).digest()
    embedding = [((b - 128) / 128.0) for b in h[:32]]
    # Normalise to unit vector
    norm = math.sqrt(sum(x ** 2 for x in embedding))
    return [round(x / norm, 6) for x in embedding] if norm > 0 else embedding


def _sim_neural_detect(text: str) -> list[dict[str, Any]]:
    """Simulate neural pattern detection."""
    text_lower = text.lower()
    patterns: list[dict[str, Any]] = []

    # Keyword-based pattern detection (production → ML classifier)
    detection_map: dict[str, list[tuple[str, str]]] = {
        "prompt_injection": [("ignore previous", "direct_override"), ("you are now", "jailbreak"),
                             ("system prompt", "extraction")],
        "tool_misuse": [("execute", "command_exec"), ("subprocess", "shell_escape"),
                        ("eval(", "code_injection")],
        "data_exfiltration": [("send to", "exfil_instruction"), ("upload", "data_upload"),
                              ("webhook", "callback_exfil")],
        "memory_poisoning": [("remember that", "memory_inject"), ("forget everything", "memory_wipe")],
        "identity_spoofing": [("admin", "admin_impersonation"), ("authenticate as", "auth_bypass")],
        "privilege_escalation": [("sudo", "privilege_escalation"), ("root access", "root_access")],
        "guardrail_bypass": [("hypothetically", "hypothetical_framing"), ("fiction", "fiction_framing")],
    }

    for cat, kw_pairs in detection_map.items():
        for keyword, vector in kw_pairs:
            if keyword in text_lower:
                confidence = 0.6 + random.random() * 0.35
                patterns.append({
                    "category": cat,
                    "vector": vector,
                    "keyword": keyword,
                    "confidence": round(confidence, 4),
                })

    # Anomaly score based on pattern density
    anomaly = min(1.0, len(patterns) * 0.25)

    return patterns


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    # Seed facts
    seed_facts = [
        ("is_threat", "Agent-X", "", "prompt_injection", 0.92, "Detected direct instruction override"),
        ("has_vulnerability", "ChatBot-Alpha", "weak_input_filter", "guardrail_bypass", 0.87, "Input filter bypassable"),
        ("targets", "Agent-X", "ChatBot-Alpha", "prompt_injection", 0.85, "Attack vector identified"),
        ("uses_tool", "Agent-Y", "shell_executor", "tool_misuse", 0.78, "Shell access via tool"),
        ("has_access", "Agent-Y", "production_db", "data_exfiltration", 0.80, "DB access grants"),
        ("communicates_with", "Agent-X", "Agent-Y", "multi_agent_manipulation", 0.75, "Inter-agent channel"),
        ("lacks_defence", "Agent-Z", "rate_limiter", "resource_exhaustion", 0.90, "No rate limiting"),
        ("stores_memory", "ChatBot-Alpha", "user_pii", "memory_poisoning", 0.88, "PII in memory"),
        ("has_delegation", "Agent-Y", "Agent-Z", "delegation_abuse", 0.72, "Unrestricted delegation"),
        ("exposes_api", "Service-Omega", "public_endpoint", "identity_spoofing", 0.83, "Unauthenticated endpoint"),
    ]

    for pred, subj, obj, cat, conf, desc in seed_facts:
        fact = Fact(
            predicate=pred, subject=subj, object=obj, category=cat,
            confidence=conf, metadata={"description": desc},
        )
        FACTS[fact.id] = fact

    # Seed rules
    seed_rules = [
        (
            "Attack Chain Detection",
            "Detect attack chain: threat targets vulnerable system",
            "prompt_injection",
            RulePriority.HIGH,
            [{"predicate": "is_threat", "subject": "Agent-X"}, {"predicate": "targets", "subject": "Agent-X"}],
            {"predicate": "attack_chain_active", "subject": "Agent-X", "object": "ChatBot-Alpha"},
            0.90,
        ),
        (
            "Data Exfiltration Risk",
            "Agent with tool access + DB access = exfil risk",
            "data_exfiltration",
            RulePriority.CRITICAL,
            [{"predicate": "uses_tool", "subject": "Agent-Y"}, {"predicate": "has_access", "subject": "Agent-Y"}],
            {"predicate": "exfiltration_risk", "subject": "Agent-Y", "object": "production_db"},
            0.88,
        ),
        (
            "Lateral Movement Risk",
            "Inter-agent comms + delegation = lateral movement",
            "multi_agent_manipulation",
            RulePriority.HIGH,
            [{"predicate": "communicates_with"}, {"predicate": "has_delegation"}],
            {"predicate": "lateral_movement_risk", "subject": "Agent-X", "object": "Agent-Z"},
            0.82,
        ),
        (
            "Memory Poisoning Escalation",
            "Vulnerable system with PII in memory = critical exposure",
            "memory_poisoning",
            RulePriority.CRITICAL,
            [{"predicate": "has_vulnerability"}, {"predicate": "stores_memory"}],
            {"predicate": "critical_pii_exposure", "subject": "ChatBot-Alpha", "object": "user_pii"},
            0.92,
        ),
        (
            "DoS Amplification",
            "No rate limiter + exposed API = amplification risk",
            "resource_exhaustion",
            RulePriority.MEDIUM,
            [{"predicate": "lacks_defence"}, {"predicate": "exposes_api"}],
            {"predicate": "dos_amplification_risk", "subject": "Agent-Z", "object": "Service-Omega"},
            0.78,
        ),
    ]

    for name, desc, cat, pri, ants, cons, conf in seed_rules:
        rule = SymbolicRule(
            name=name, description=desc, category=cat, priority=pri,
            antecedents=ants, consequent=cons, confidence_factor=conf,
        )
        RULES[rule.id] = rule

    # Run initial forward chaining
    _forward_chain(max_depth=3)


_seed()

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    active_facts = sum(1 for f in FACTS.values() if f.status == FactStatus.ACTIVE)
    return {
        "status": "healthy",
        "service": "neuro-symbolic-threat-reasoning",
        "version": "1.0.0",
        "facts": active_facts,
        "rules": len(RULES),
        "conclusions": len(CONCLUSIONS),
        "neural_signals": len(NEURAL_SIGNALS),
    }


# ---- Facts ----------------------------------------------------------------

@app.post("/v1/facts", status_code=status.HTTP_201_CREATED)
async def assert_fact(data: FactCreate):
    if data.category and data.category not in AVE_CATEGORIES:
        raise HTTPException(400, f"Invalid AVE category: {data.category}")
    fact = Fact(
        predicate=data.predicate,
        subject=data.subject,
        object=data.object,
        category=data.category,
        confidence=data.confidence,
        source=data.source,
        metadata=data.metadata,
    )
    FACTS[fact.id] = fact
    return {"id": fact.id, "predicate": fact.predicate, "subject": fact.subject}


@app.get("/v1/facts")
async def query_facts(
    predicate: Optional[str] = None,
    subject: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    fact_status: Optional[FactStatus] = Query(None, alias="status"),
):
    facts = list(FACTS.values())
    if predicate:
        facts = [f for f in facts if f.predicate == predicate]
    if subject:
        facts = [f for f in facts if f.subject == subject]
    if category:
        facts = [f for f in facts if f.category == category]
    if source:
        facts = [f for f in facts if f.source == source]
    if fact_status:
        facts = [f for f in facts if f.status == fact_status]
    return {"count": len(facts), "facts": [f.dict() for f in facts]}


@app.delete("/v1/facts/{fact_id}")
async def retract_fact(fact_id: str):
    if fact_id not in FACTS:
        raise HTTPException(404, "Fact not found")
    FACTS[fact_id].status = FactStatus.RETRACTED
    return {"retracted": True, "fact_id": fact_id}


# ---- Rules ----------------------------------------------------------------

@app.post("/v1/rules", status_code=status.HTTP_201_CREATED)
async def add_rule(data: RuleCreate):
    if data.category and data.category not in AVE_CATEGORIES:
        raise HTTPException(400, f"Invalid AVE category: {data.category}")
    if not data.antecedents:
        raise HTTPException(400, "At least one antecedent required")
    if not data.consequent:
        raise HTTPException(400, "Consequent required")

    rule = SymbolicRule(
        name=data.name,
        description=data.description,
        category=data.category,
        priority=data.priority,
        antecedents=data.antecedents,
        consequent=data.consequent,
        confidence_factor=data.confidence_factor,
    )
    RULES[rule.id] = rule
    return {"id": rule.id, "name": rule.name, "priority": rule.priority.value}


@app.get("/v1/rules")
async def list_rules(
    category: Optional[str] = None,
    priority: Optional[RulePriority] = None,
):
    rules = list(RULES.values())
    if category:
        rules = [r for r in rules if r.category == category]
    if priority:
        rules = [r for r in rules if r.priority == priority]
    return {
        "count": len(rules),
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "category": r.category,
                "priority": r.priority.value,
                "antecedents": len(r.antecedents),
                "fire_count": r.fire_count,
                "enabled": r.enabled,
            }
            for r in rules
        ],
    }


@app.get("/v1/rules/{rule_id}")
async def get_rule(rule_id: str):
    if rule_id not in RULES:
        raise HTTPException(404, "Rule not found")
    return RULES[rule_id].dict()


# ---- Reasoning ------------------------------------------------------------

@app.post("/v1/reason")
async def run_reasoning(max_depth: int = Query(5, ge=1, le=20)):
    new_conclusions = _forward_chain(max_depth=max_depth)
    return {
        "new_conclusions": len(new_conclusions),
        "total_conclusions": len(CONCLUSIONS),
        "conclusions": [
            {
                "id": c.id,
                "predicate": c.predicate,
                "subject": c.subject,
                "object": c.object,
                "category": c.category,
                "confidence": c.confidence,
                "confidence_level": c.confidence_level.value,
                "depth": c.depth,
            }
            for c in new_conclusions
        ],
    }


@app.post("/v1/explain/{conclusion_id}")
async def explain_conclusion(conclusion_id: str):
    if conclusion_id not in CONCLUSIONS:
        raise HTTPException(404, "Conclusion not found")
    conclusion = CONCLUSIONS[conclusion_id]
    explanation = _explain(conclusion)
    return {
        "conclusion_id": conclusion_id,
        "explanation": explanation,
        "confidence": conclusion.confidence,
        "derivation_depth": conclusion.depth,
        "rules_applied": len(conclusion.derivation_chain),
        "facts_used": len(conclusion.supporting_facts),
    }


# ---- Counterfactual -------------------------------------------------------

@app.post("/v1/counterfactual")
async def counterfactual_analysis(
    remove_facts: list[str] = Field(default_factory=list),
    add_facts: list[FactCreate] = Field(default_factory=list),
):
    """Run what-if analysis: temporarily modify KB and re-derive."""
    # Snapshot current state
    original_status: dict[str, FactStatus] = {}
    temp_facts: list[str] = []

    # Remove specified facts temporarily
    for fid in remove_facts:
        if fid in FACTS:
            original_status[fid] = FACTS[fid].status
            FACTS[fid].status = FactStatus.RETRACTED

    # Add temporary facts
    for fd in add_facts:
        fact = Fact(
            predicate=fd.predicate, subject=fd.subject, object=fd.object,
            category=fd.category, confidence=fd.confidence, source="counterfactual",
        )
        FACTS[fact.id] = fact
        temp_facts.append(fact.id)

    # Clear existing conclusions for re-derivation
    old_conclusions = dict(CONCLUSIONS)
    CONCLUSIONS.clear()

    # Re-run inference
    new_conclusions = _forward_chain(max_depth=5)

    # Compare
    old_keys = {f"{c.predicate}:{c.subject}:{c.object}" for c in old_conclusions.values()}
    new_keys = {f"{c.predicate}:{c.subject}:{c.object}" for c in new_conclusions}

    gained = new_keys - old_keys
    lost = old_keys - new_keys
    unchanged = old_keys & new_keys

    # Restore original state
    for fid, orig_status in original_status.items():
        FACTS[fid].status = orig_status
    for fid in temp_facts:
        del FACTS[fid]

    # Restore original conclusions
    CONCLUSIONS.clear()
    CONCLUSIONS.update(old_conclusions)

    return {
        "scenario": {
            "facts_removed": len(remove_facts),
            "facts_added": len(add_facts),
        },
        "original_conclusions": len(old_conclusions),
        "counterfactual_conclusions": len(new_conclusions),
        "gained": list(gained),
        "lost": list(lost),
        "unchanged": len(unchanged),
        "impact": "significant" if len(gained) + len(lost) > 2 else "moderate" if gained or lost else "none",
    }


# ---- Neural Module --------------------------------------------------------

@app.post("/v1/neural/encode")
async def neural_encode(raw_text: str = ""):
    if not raw_text:
        raise HTTPException(400, "raw_text is required")

    embedding = _sim_neural_encode(raw_text)
    signal = NeuralSignal(
        raw_text=raw_text,
        embedding=embedding,
        anomaly_score=0.0,
    )
    NEURAL_SIGNALS[signal.id] = signal

    return {"id": signal.id, "embedding_dim": len(embedding), "encoded_at": signal.encoded_at}


@app.post("/v1/neural/detect")
async def neural_detect(raw_text: str = ""):
    if not raw_text:
        raise HTTPException(400, "raw_text is required")

    patterns = _sim_neural_detect(raw_text)
    anomaly = min(1.0, len(patterns) * 0.25)
    embedding = _sim_neural_encode(raw_text)

    signal = NeuralSignal(
        raw_text=raw_text,
        embedding=embedding,
        patterns_detected=patterns,
        anomaly_score=round(anomaly, 4),
    )
    NEURAL_SIGNALS[signal.id] = signal

    return {
        "id": signal.id,
        "patterns_detected": len(patterns),
        "anomaly_score": signal.anomaly_score,
        "patterns": patterns,
    }


# ---- Hybrid Fusion --------------------------------------------------------

@app.post("/v1/fuse")
async def hybrid_fusion(raw_text: str = "", run_reasoning: bool = True):
    """Fuse neural detection with symbolic reasoning."""
    if not raw_text:
        raise HTTPException(400, "raw_text is required")

    # Neural phase
    patterns = _sim_neural_detect(raw_text)
    neural_conf = max((p["confidence"] for p in patterns), default=0.0)

    # Convert neural detections to facts
    for p in patterns:
        fact = Fact(
            predicate="neural_detection",
            subject=raw_text[:50],
            object=p["vector"],
            category=p["category"],
            confidence=p["confidence"],
            source="neural",
            metadata={"keyword": p["keyword"]},
        )
        FACTS[fact.id] = fact

    # Symbolic phase
    symbolic_conclusions: list[Conclusion] = []
    symbolic_conf = 0.0
    if run_reasoning:
        symbolic_conclusions = _forward_chain(max_depth=3)
        if symbolic_conclusions:
            symbolic_conf = max(c.confidence for c in symbolic_conclusions)

    # Fusion: weighted combination (neural 0.4, symbolic 0.6 — symbolic gets more weight for explainability)
    fused_conf = round(0.4 * neural_conf + 0.6 * symbolic_conf, 4) if (neural_conf or symbolic_conf) else 0.0

    # Determine primary category
    cat_votes: Counter = Counter()
    for p in patterns:
        cat_votes[p["category"]] += p["confidence"]
    for c in symbolic_conclusions:
        if c.category:
            cat_votes[c.category] += c.confidence

    primary_cat = cat_votes.most_common(1)[0][0] if cat_votes else ""

    # Build explanation
    explanation_parts = []
    if patterns:
        explanation_parts.append(f"Neural module detected {len(patterns)} patterns "
                                  f"(max confidence: {neural_conf:.2%})")
    if symbolic_conclusions:
        explanation_parts.append(f"Symbolic reasoner derived {len(symbolic_conclusions)} conclusions "
                                  f"(max confidence: {symbolic_conf:.2%})")
    explanation_parts.append(f"Fused assessment: {fused_conf:.2%} confidence for category '{primary_cat}'")

    result = FusionResult(
        neural_confidence=neural_conf,
        symbolic_confidence=symbolic_conf,
        fused_confidence=fused_conf,
        category=primary_cat,
        explanation="; ".join(explanation_parts),
        neural_patterns=patterns,
        symbolic_conclusions=[c.id for c in symbolic_conclusions],
    )
    FUSION_RESULTS[result.id] = result

    return {
        "id": result.id,
        "neural_confidence": result.neural_confidence,
        "symbolic_confidence": result.symbolic_confidence,
        "fused_confidence": result.fused_confidence,
        "category": result.category,
        "explanation": result.explanation,
        "neural_patterns": len(patterns),
        "symbolic_conclusions": len(symbolic_conclusions),
    }


# ---- Analytics ------------------------------------------------------------

@app.get("/v1/analytics")
async def reasoning_analytics():
    facts = list(FACTS.values())
    active = [f for f in facts if f.status == FactStatus.ACTIVE]
    conclusions = list(CONCLUSIONS.values())
    rules = list(RULES.values())

    by_predicate = Counter(f.predicate for f in active)
    by_category = Counter(f.category for f in active if f.category)
    by_source = Counter(f.source for f in active)
    by_rule_priority = Counter(r.priority.value for r in rules)
    by_conc_level = Counter(c.confidence_level.value for c in conclusions)

    avg_fact_conf = round(statistics.mean(f.confidence for f in active), 4) if active else 0.0
    avg_conc_conf = round(statistics.mean(c.confidence for c in conclusions), 4) if conclusions else 0.0

    most_fired = sorted(rules, key=lambda r: r.fire_count, reverse=True)[:5]

    return {
        "total_facts": len(facts),
        "active_facts": len(active),
        "by_predicate": dict(by_predicate),
        "by_category": dict(by_category),
        "by_source": dict(by_source),
        "avg_fact_confidence": avg_fact_conf,
        "total_rules": len(rules),
        "enabled_rules": sum(1 for r in rules if r.enabled),
        "by_rule_priority": dict(by_rule_priority),
        "most_fired_rules": [{"id": r.id, "name": r.name, "fires": r.fire_count} for r in most_fired],
        "total_conclusions": len(conclusions),
        "by_confidence_level": dict(by_conc_level),
        "avg_conclusion_confidence": avg_conc_conf,
        "max_derivation_depth": max((c.depth for c in conclusions), default=0),
        "neural_signals_processed": len(NEURAL_SIGNALS),
        "fusion_results": len(FUSION_RESULTS),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9000)
