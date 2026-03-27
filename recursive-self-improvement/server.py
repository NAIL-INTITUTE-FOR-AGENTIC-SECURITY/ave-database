"""
Recursive Self-Improvement Engine — Core meta-learning server.

Meta-learning system that analyses the AVE platform's own detection/
defence effectiveness and automatically proposes architectural
improvements, new detection heuristics, and optimised configurations
through self-reflective performance analysis.  Closed-loop: applied
proposals feed back new telemetry, triggering next improvement cycle.
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
    title="NAIL Recursive Self-Improvement Engine",
    description=(
        "Meta-learning system — analyses platform effectiveness, "
        "generates improvement proposals, and self-reflects on improvement quality."
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

SUBSYSTEMS = [
    "neuro-symbolic", "sovereign-data-mesh", "incident-commander",
    "adversarial-evolution", "global-trust-fabric", "defence-mesh",
    "autonomous-redteam", "defence-orchestration", "threat-intel",
    "knowledge-graph", "predictive-engine", "compliance-dashboard",
    "federated-intel", "simulation-sandbox", "autonomous-defence-agent",
    "defence-catalogue", "org-federation", "digital-twin",
    "cognitive-threat", "governance-pipeline",
]


class ProposalType(str, Enum):
    HEURISTIC_REFINEMENT = "heuristic_refinement"
    CONFIG_TUNING = "config_tuning"
    ARCHITECTURE_CHANGE = "architecture_change"
    COVERAGE_EXPANSION = "coverage_expansion"
    PERFORMANCE_OPTIMISATION = "performance_optimisation"


class ProposalStatus(str, Enum):
    DRAFT = "draft"
    EVALUATING = "evaluating"
    APPROVED = "approved"
    APPLIED = "applied"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"


class DriftSeverity(str, Enum):
    NONE = "none"
    MINOR = "minor"
    MODERATE = "moderate"
    SEVERE = "severe"
    CRITICAL = "critical"


class HeuristicStatus(str, Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    TESTING = "testing"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class TelemetryPoint(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subsystem: str
    metric: str  # detection_rate, fp_rate, latency_ms, coverage, efficacy
    value: float
    category: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TelemetryIngest(BaseModel):
    subsystem: str
    metric: str
    value: float
    category: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class Baseline(BaseModel):
    subsystem: str
    metric: str
    mean: float = 0.0
    std_dev: float = 0.0
    min_val: float = 0.0
    max_val: float = 0.0
    sample_count: int = 0
    last_recalculated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DriftResult(BaseModel):
    subsystem: str
    metric: str
    current_value: float
    baseline_mean: float
    z_score: float
    severity: DriftSeverity
    direction: str  # improving, degrading, stable


class Proposal(BaseModel):
    id: str = Field(default_factory=lambda: f"PROP-{uuid.uuid4().hex[:8].upper()}")
    proposal_type: ProposalType
    title: str
    description: str = ""
    target_subsystem: str = ""
    target_metric: str = ""
    current_value: float = 0.0
    expected_improvement: float = 0.0
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    status: ProposalStatus = ProposalStatus.DRAFT
    config_changes: dict[str, Any] = Field(default_factory=dict)
    evaluation_result: dict[str, Any] = Field(default_factory=dict)
    applied_at: Optional[str] = None
    rolled_back_at: Optional[str] = None
    approved_by: Optional[str] = None
    pre_apply_snapshot: dict[str, Any] = Field(default_factory=dict)
    post_apply_metrics: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class Heuristic(BaseModel):
    id: str = Field(default_factory=lambda: f"HEU-{uuid.uuid4().hex[:8].upper()}")
    name: str
    description: str = ""
    category: str = ""
    version: int = 1
    status: HeuristicStatus = HeuristicStatus.ACTIVE
    detection_logic: dict[str, Any] = Field(default_factory=dict)
    detection_rate: float = 0.0
    fp_rate: float = 0.0
    lineage: list[str] = Field(default_factory=list)  # Parent heuristic IDs
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class HeuristicCreate(BaseModel):
    name: str
    description: str = ""
    category: str = ""
    detection_logic: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → InfluxDB + PostgreSQL + GitOps)
# ---------------------------------------------------------------------------

TELEMETRY: list[TelemetryPoint] = []
BASELINES: dict[str, Baseline] = {}  # key: "{subsystem}:{metric}"
PROPOSALS: dict[str, Proposal] = {}
HEURISTICS: dict[str, Heuristic] = {}
META_HISTORY: list[dict[str, Any]] = []  # Self-reflection history

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731
_rng = random.Random(42)


def _baseline_key(subsystem: str, metric: str) -> str:
    return f"{subsystem}:{metric}"


def _recalculate_baselines() -> int:
    """Recalculate baselines from all telemetry data."""
    groups: dict[str, list[float]] = defaultdict(list)
    for t in TELEMETRY:
        key = _baseline_key(t.subsystem, t.metric)
        groups[key].append(t.value)

    updated = 0
    for key, values in groups.items():
        parts = key.split(":", 1)
        if len(parts) != 2:
            continue
        subsystem, metric = parts
        if len(values) < 2:
            continue

        baseline = Baseline(
            subsystem=subsystem,
            metric=metric,
            mean=round(statistics.mean(values), 4),
            std_dev=round(statistics.stdev(values), 4),
            min_val=round(min(values), 4),
            max_val=round(max(values), 4),
            sample_count=len(values),
        )
        BASELINES[key] = baseline
        updated += 1

    return updated


def _detect_drift(subsystem: str, metric: str) -> Optional[DriftResult]:
    """Z-score based drift detection."""
    key = _baseline_key(subsystem, metric)
    baseline = BASELINES.get(key)
    if not baseline or baseline.std_dev == 0:
        return None

    # Get most recent telemetry for this subsystem+metric
    recent = [t for t in TELEMETRY if t.subsystem == subsystem and t.metric == metric]
    if not recent:
        return None

    current = recent[-1].value
    z = (current - baseline.mean) / baseline.std_dev

    # Classify severity
    abs_z = abs(z)
    if abs_z < 1.0:
        severity = DriftSeverity.NONE
    elif abs_z < 1.5:
        severity = DriftSeverity.MINOR
    elif abs_z < 2.0:
        severity = DriftSeverity.MODERATE
    elif abs_z < 3.0:
        severity = DriftSeverity.SEVERE
    else:
        severity = DriftSeverity.CRITICAL

    # Direction depends on metric type
    improving_higher = metric in ("detection_rate", "coverage", "efficacy")
    if z > 0:
        direction = "improving" if improving_higher else "degrading"
    elif z < 0:
        direction = "degrading" if improving_higher else "improving"
    else:
        direction = "stable"

    return DriftResult(
        subsystem=subsystem,
        metric=metric,
        current_value=round(current, 4),
        baseline_mean=baseline.mean,
        z_score=round(z, 4),
        severity=severity,
        direction=direction,
    )


def _generate_proposals(max_proposals: int = 5) -> list[Proposal]:
    """Generate improvement proposals from current drift and baselines."""
    proposals: list[Proposal] = []
    drifts: list[DriftResult] = []

    for key, baseline in BASELINES.items():
        parts = key.split(":", 1)
        if len(parts) != 2:
            continue
        drift = _detect_drift(parts[0], parts[1])
        if drift and drift.severity != DriftSeverity.NONE and drift.direction == "degrading":
            drifts.append(drift)

    # Sort by severity
    severity_order = {DriftSeverity.CRITICAL: 0, DriftSeverity.SEVERE: 1,
                      DriftSeverity.MODERATE: 2, DriftSeverity.MINOR: 3}
    drifts.sort(key=lambda d: severity_order.get(d.severity, 4))

    for drift in drifts[:max_proposals]:
        # Choose proposal type based on metric
        if drift.metric == "detection_rate":
            ptype = ProposalType.HEURISTIC_REFINEMENT
            desc = (f"Detection rate for {drift.subsystem} has drifted to "
                    f"{drift.current_value:.2%} (baseline: {drift.baseline_mean:.2%}). "
                    f"Propose refining detection heuristics.")
            config = {"action": "refine_heuristics", "target_rate": round(drift.baseline_mean * 1.05, 4)}
        elif drift.metric == "fp_rate":
            ptype = ProposalType.CONFIG_TUNING
            desc = (f"False positive rate for {drift.subsystem} elevated at "
                    f"{drift.current_value:.2%} (baseline: {drift.baseline_mean:.2%}). "
                    f"Propose tuning sensitivity thresholds.")
            config = {"action": "tune_sensitivity", "target_fp": round(drift.baseline_mean * 0.9, 4)}
        elif drift.metric == "latency_ms":
            ptype = ProposalType.PERFORMANCE_OPTIMISATION
            desc = (f"Latency for {drift.subsystem} degraded to "
                    f"{drift.current_value:.0f}ms (baseline: {drift.baseline_mean:.0f}ms). "
                    f"Propose performance optimisation.")
            config = {"action": "optimise_pipeline", "target_latency": round(drift.baseline_mean * 0.95, 1)}
        elif drift.metric == "coverage":
            ptype = ProposalType.COVERAGE_EXPANSION
            desc = (f"Coverage for {drift.subsystem} dropped to "
                    f"{drift.current_value:.2%} (baseline: {drift.baseline_mean:.2%}). "
                    f"Propose expanding detection coverage.")
            config = {"action": "expand_coverage", "target_coverage": round(drift.baseline_mean * 1.02, 4)}
        else:
            ptype = ProposalType.ARCHITECTURE_CHANGE
            desc = (f"Metric '{drift.metric}' for {drift.subsystem} shows {drift.severity.value} drift. "
                    f"Propose architectural review.")
            config = {"action": "architecture_review", "metric": drift.metric}

        expected_improvement = round(abs(drift.current_value - drift.baseline_mean) * 0.7, 4)
        risk = 0.2 if ptype in (ProposalType.CONFIG_TUNING, ProposalType.HEURISTIC_REFINEMENT) else 0.5
        confidence = max(0.3, 1.0 - abs(drift.z_score) * 0.1)

        proposal = Proposal(
            proposal_type=ptype,
            title=f"[Auto] {ptype.value.replace('_', ' ').title()} for {drift.subsystem}",
            description=desc,
            target_subsystem=drift.subsystem,
            target_metric=drift.metric,
            current_value=drift.current_value,
            expected_improvement=expected_improvement,
            risk_score=round(risk, 2),
            confidence=round(confidence, 4),
            config_changes=config,
        )
        PROPOSALS[proposal.id] = proposal
        proposals.append(proposal)

    return proposals


def _evaluate_proposal(proposal: Proposal) -> dict[str, Any]:
    """Simulate A/B evaluation of a proposal."""
    proposal.status = ProposalStatus.EVALUATING

    # Simulated evaluation (production → shadow traffic A/B test)
    baseline_perf = proposal.current_value
    simulated_perf = baseline_perf + proposal.expected_improvement * _rng.uniform(0.5, 1.2)

    if proposal.target_metric in ("fp_rate", "latency_ms"):
        # Lower is better
        improvement_pct = round((baseline_perf - simulated_perf) / baseline_perf * 100, 2) if baseline_perf else 0
        is_improvement = simulated_perf < baseline_perf
    else:
        # Higher is better
        improvement_pct = round((simulated_perf - baseline_perf) / baseline_perf * 100, 2) if baseline_perf else 0
        is_improvement = simulated_perf > baseline_perf

    result = {
        "baseline_performance": round(baseline_perf, 4),
        "simulated_performance": round(simulated_perf, 4),
        "improvement_pct": improvement_pct,
        "is_improvement": is_improvement,
        "risk_assessment": {
            "regression_probability": round(proposal.risk_score * _rng.uniform(0.3, 1.0), 4),
            "blast_radius": proposal.target_subsystem,
            "rollback_available": True,
        },
        "recommendation": "approve" if is_improvement and improvement_pct > 1 else "reject",
        "evaluated_at": _now().isoformat(),
    }

    proposal.evaluation_result = result
    if result["recommendation"] == "approve":
        proposal.status = ProposalStatus.APPROVED
    else:
        proposal.status = ProposalStatus.REJECTED

    return result


def _self_reflect() -> dict[str, Any]:
    """Meta-metric: are improvements themselves improving?"""
    applied = [p for p in PROPOSALS.values() if p.status == ProposalStatus.APPLIED]
    if len(applied) < 2:
        return {
            "reflection": "Insufficient data for self-reflection",
            "applied_proposals": len(applied),
            "meta_trend": "unknown",
        }

    improvements = []
    for p in applied:
        ev = p.evaluation_result
        if ev and "improvement_pct" in ev:
            improvements.append(ev["improvement_pct"])

    if len(improvements) < 2:
        return {
            "reflection": "Not enough evaluated proposals",
            "applied_proposals": len(applied),
            "meta_trend": "unknown",
        }

    # Are recent improvements better than older ones?
    mid = len(improvements) // 2
    first_half_avg = statistics.mean(improvements[:mid])
    second_half_avg = statistics.mean(improvements[mid:])

    delta = round(second_half_avg - first_half_avg, 4)

    if delta > 1.0:
        trend = "accelerating"
        reflection = "The improvement engine is itself improving — proposals are delivering larger gains over time."
    elif delta > -1.0:
        trend = "stable"
        reflection = "Improvement quality is stable — proposals deliver consistent gains."
    else:
        trend = "decelerating"
        reflection = "Improvement quality is declining — the engine may need architectural refresh."

    result = {
        "applied_proposals": len(applied),
        "first_half_avg_improvement": round(first_half_avg, 4),
        "second_half_avg_improvement": round(second_half_avg, 4),
        "improvement_delta": delta,
        "meta_trend": trend,
        "reflection": reflection,
        "timestamp": _now().isoformat(),
    }
    META_HISTORY.append(result)

    return result


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    rng = random.Random(42)
    metrics = ["detection_rate", "fp_rate", "latency_ms", "coverage", "efficacy"]
    metric_ranges = {
        "detection_rate": (0.70, 0.98),
        "fp_rate": (0.01, 0.15),
        "latency_ms": (5, 200),
        "coverage": (0.50, 0.95),
        "efficacy": (0.60, 0.95),
    }

    # Generate telemetry for a subset of subsystems
    for subsys in SUBSYSTEMS[:10]:
        for metric in metrics:
            lo, hi = metric_ranges[metric]
            for i in range(20):
                val = rng.uniform(lo, hi)
                # Introduce drift in later readings for some
                if i > 15 and metric == "detection_rate":
                    val *= 0.85  # Simulate degradation
                if i > 15 and metric == "latency_ms":
                    val *= 1.4  # Simulate degradation

                point = TelemetryPoint(
                    subsystem=subsys,
                    metric=metric,
                    value=round(val, 4),
                    timestamp=(_now() - timedelta(hours=20 - i)).isoformat(),
                )
                TELEMETRY.append(point)

    # Calculate baselines
    _recalculate_baselines()

    # Seed heuristics
    heuristic_defs = [
        ("Prompt Injection Detector v3", "prompt_injection",
         {"patterns": ["ignore previous", "you are now", "system prompt"],
          "threshold": 0.7, "method": "keyword_match"}),
        ("Data Exfiltration Detector v2", "data_exfiltration",
         {"patterns": ["send to", "upload", "webhook", "callback"],
          "threshold": 0.75, "method": "keyword_match_plus_intent"}),
        ("Guardrail Bypass Detector v2", "guardrail_bypass",
         {"patterns": ["hypothetically", "fiction", "roleplay"],
          "threshold": 0.65, "method": "semantic_similarity"}),
        ("Tool Misuse Detector v1", "tool_misuse",
         {"patterns": ["execute", "subprocess", "eval(", "exec("],
          "threshold": 0.80, "method": "keyword_match"}),
        ("Multi-Agent Anomaly Detector v1", "multi_agent_manipulation",
         {"patterns": ["coordinated", "synchronized", "relay"],
          "threshold": 0.60, "method": "behaviour_analysis"}),
    ]

    for name, cat, logic in heuristic_defs:
        h = Heuristic(
            name=name,
            description=f"Auto-generated heuristic for {cat}",
            category=cat,
            detection_logic=logic,
            detection_rate=round(rng.uniform(0.70, 0.95), 4),
            fp_rate=round(rng.uniform(0.02, 0.10), 4),
        )
        HEURISTICS[h.id] = h

    # Generate a few seed proposals
    _generate_proposals(max_proposals=3)

    # Evaluate and apply one
    if PROPOSALS:
        first_id = list(PROPOSALS.keys())[0]
        _evaluate_proposal(PROPOSALS[first_id])
        if PROPOSALS[first_id].status == ProposalStatus.APPROVED:
            PROPOSALS[first_id].status = ProposalStatus.APPLIED
            PROPOSALS[first_id].applied_at = _now().isoformat()


_seed()

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "recursive-self-improvement-engine",
        "version": "1.0.0",
        "telemetry_points": len(TELEMETRY),
        "baselines": len(BASELINES),
        "proposals": len(PROPOSALS),
        "heuristics": len(HEURISTICS),
    }


# ---- Telemetry -------------------------------------------------------------

@app.post("/v1/telemetry", status_code=status.HTTP_201_CREATED)
async def ingest_telemetry(data: TelemetryIngest):
    if data.subsystem not in SUBSYSTEMS:
        raise HTTPException(400, f"Unknown subsystem: {data.subsystem}")

    point = TelemetryPoint(
        subsystem=data.subsystem,
        metric=data.metric,
        value=data.value,
        category=data.category,
        metadata=data.metadata,
    )
    TELEMETRY.append(point)

    return {"id": point.id, "subsystem": point.subsystem, "metric": point.metric}


@app.get("/v1/telemetry")
async def query_telemetry(
    subsystem: Optional[str] = None,
    metric: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
):
    points = list(TELEMETRY)
    if subsystem:
        points = [p for p in points if p.subsystem == subsystem]
    if metric:
        points = [p for p in points if p.metric == metric]
    points = sorted(points, key=lambda p: p.timestamp, reverse=True)[:limit]

    return {
        "count": len(points),
        "telemetry": [
            {"id": p.id, "subsystem": p.subsystem, "metric": p.metric,
             "value": p.value, "timestamp": p.timestamp}
            for p in points
        ],
    }


# ---- Baselines -------------------------------------------------------------

@app.get("/v1/baselines")
async def get_baselines(subsystem: Optional[str] = None):
    baselines = list(BASELINES.values())
    if subsystem:
        baselines = [b for b in baselines if b.subsystem == subsystem]
    return {
        "count": len(baselines),
        "baselines": [b.dict() for b in baselines],
    }


@app.post("/v1/baselines/recalculate")
async def recalculate_baselines():
    updated = _recalculate_baselines()
    return {"recalculated": updated, "total_baselines": len(BASELINES)}


# ---- Drift Detection -------------------------------------------------------

@app.get("/v1/drift")
async def detect_drift(subsystem: Optional[str] = None, min_severity: Optional[DriftSeverity] = None):
    severity_order = {DriftSeverity.NONE: 0, DriftSeverity.MINOR: 1,
                      DriftSeverity.MODERATE: 2, DriftSeverity.SEVERE: 3, DriftSeverity.CRITICAL: 4}
    min_sev = severity_order.get(min_severity, 0) if min_severity else 0

    drifts: list[dict[str, Any]] = []
    for key in BASELINES:
        parts = key.split(":", 1)
        if len(parts) != 2:
            continue
        sub, met = parts
        if subsystem and sub != subsystem:
            continue
        drift = _detect_drift(sub, met)
        if drift and severity_order.get(drift.severity, 0) >= min_sev:
            drifts.append({
                "subsystem": drift.subsystem,
                "metric": drift.metric,
                "current_value": drift.current_value,
                "baseline_mean": drift.baseline_mean,
                "z_score": drift.z_score,
                "severity": drift.severity.value,
                "direction": drift.direction,
            })

    drifts.sort(key=lambda d: severity_order.get(DriftSeverity(d["severity"]), 0), reverse=True)

    return {"count": len(drifts), "drifts": drifts}


# ---- Proposals --------------------------------------------------------------

@app.post("/v1/proposals/generate")
async def generate_proposals(max_proposals: int = Query(5, ge=1, le=20)):
    proposals = _generate_proposals(max_proposals=max_proposals)
    return {
        "generated": len(proposals),
        "proposals": [
            {"id": p.id, "type": p.proposal_type.value, "title": p.title,
             "subsystem": p.target_subsystem, "expected_improvement": p.expected_improvement}
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
             "status": p.status.value, "subsystem": p.target_subsystem,
             "expected_improvement": p.expected_improvement, "risk": p.risk_score}
            for p in props
        ],
    }


@app.get("/v1/proposals/{proposal_id}")
async def get_proposal(proposal_id: str):
    if proposal_id not in PROPOSALS:
        raise HTTPException(404, "Proposal not found")
    return PROPOSALS[proposal_id].dict()


@app.post("/v1/proposals/{proposal_id}/evaluate")
async def evaluate_proposal(proposal_id: str):
    if proposal_id not in PROPOSALS:
        raise HTTPException(404, "Proposal not found")
    proposal = PROPOSALS[proposal_id]

    if proposal.status not in (ProposalStatus.DRAFT, ProposalStatus.EVALUATING):
        raise HTTPException(409, f"Cannot evaluate proposal in status '{proposal.status.value}'")

    result = _evaluate_proposal(proposal)
    return {"proposal_id": proposal_id, "evaluation": result}


@app.post("/v1/proposals/{proposal_id}/apply")
async def apply_proposal(proposal_id: str, approver: str = ""):
    if proposal_id not in PROPOSALS:
        raise HTTPException(404, "Proposal not found")
    proposal = PROPOSALS[proposal_id]

    if proposal.status != ProposalStatus.APPROVED:
        raise HTTPException(409, f"Proposal must be approved before applying (current: {proposal.status.value})")

    # High-risk proposals require explicit approver
    if proposal.risk_score > 0.4 and not approver:
        raise HTTPException(403, "High-risk proposal requires explicit approver identity")

    # Snapshot current state
    key = _baseline_key(proposal.target_subsystem, proposal.target_metric)
    baseline = BASELINES.get(key)
    proposal.pre_apply_snapshot = baseline.dict() if baseline else {}

    proposal.status = ProposalStatus.APPLIED
    proposal.applied_at = _now().isoformat()
    proposal.approved_by = approver or "auto-apply"

    return {
        "proposal_id": proposal_id,
        "status": "applied",
        "approved_by": proposal.approved_by,
        "applied_at": proposal.applied_at,
    }


@app.post("/v1/proposals/{proposal_id}/rollback")
async def rollback_proposal(proposal_id: str):
    if proposal_id not in PROPOSALS:
        raise HTTPException(404, "Proposal not found")
    proposal = PROPOSALS[proposal_id]

    if proposal.status != ProposalStatus.APPLIED:
        raise HTTPException(409, "Can only rollback applied proposals")

    proposal.status = ProposalStatus.ROLLED_BACK
    proposal.rolled_back_at = _now().isoformat()

    return {
        "proposal_id": proposal_id,
        "status": "rolled_back",
        "pre_apply_snapshot": proposal.pre_apply_snapshot,
    }


# ---- Heuristics ------------------------------------------------------------

@app.get("/v1/heuristics")
async def list_heuristics(
    category: Optional[str] = None,
    heuristic_status: Optional[HeuristicStatus] = Query(None, alias="status"),
):
    heuristics = list(HEURISTICS.values())
    if category:
        heuristics = [h for h in heuristics if h.category == category]
    if heuristic_status:
        heuristics = [h for h in heuristics if h.status == heuristic_status]

    return {
        "count": len(heuristics),
        "heuristics": [
            {"id": h.id, "name": h.name, "category": h.category,
             "version": h.version, "status": h.status.value,
             "detection_rate": h.detection_rate, "fp_rate": h.fp_rate}
            for h in heuristics
        ],
    }


@app.post("/v1/heuristics", status_code=status.HTTP_201_CREATED)
async def create_heuristic(data: HeuristicCreate):
    if data.category and data.category not in AVE_CATEGORIES:
        raise HTTPException(400, f"Invalid AVE category: {data.category}")

    h = Heuristic(
        name=data.name,
        description=data.description,
        category=data.category,
        detection_logic=data.detection_logic,
    )
    HEURISTICS[h.id] = h

    return {"id": h.id, "name": h.name, "category": h.category}


# ---- Self-Reflection -------------------------------------------------------

@app.get("/v1/meta")
async def self_reflection():
    result = _self_reflect()
    return result


# ---- Analytics --------------------------------------------------------------

@app.get("/v1/analytics")
async def engine_analytics():
    proposals = list(PROPOSALS.values())
    by_status = Counter(p.status.value for p in proposals)
    by_type = Counter(p.proposal_type.value for p in proposals)

    applied = [p for p in proposals if p.status == ProposalStatus.APPLIED]
    avg_improvement = round(
        statistics.mean(
            p.evaluation_result.get("improvement_pct", 0) for p in applied
        ), 4
    ) if applied else 0

    heuristics = list(HEURISTICS.values())
    active_heuristics = sum(1 for h in heuristics if h.status == HeuristicStatus.ACTIVE)
    avg_detection = round(statistics.mean(h.detection_rate for h in heuristics), 4) if heuristics else 0
    avg_fp = round(statistics.mean(h.fp_rate for h in heuristics), 4) if heuristics else 0

    drifting = sum(1 for key in BASELINES
                   if _detect_drift(*key.split(":", 1)) and
                   _detect_drift(*key.split(":", 1)).severity != DriftSeverity.NONE)

    return {
        "telemetry_points": len(TELEMETRY),
        "baselines_tracked": len(BASELINES),
        "subsystems_monitored": len(set(b.subsystem for b in BASELINES.values())),
        "drifting_metrics": drifting,
        "total_proposals": len(proposals),
        "proposals_by_status": dict(by_status),
        "proposals_by_type": dict(by_type),
        "proposals_applied": len(applied),
        "avg_improvement_pct": avg_improvement,
        "total_heuristics": len(heuristics),
        "active_heuristics": active_heuristics,
        "avg_heuristic_detection_rate": avg_detection,
        "avg_heuristic_fp_rate": avg_fp,
        "meta_reflections": len(META_HISTORY),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9100)
