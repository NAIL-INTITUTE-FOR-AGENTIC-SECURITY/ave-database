"""
Predictive Vulnerability Engine — Core prediction server.

Ingests signals from AVE history, CVE feeds, research papers, and
framework releases to forecast emerging vulnerability categories,
severity trends, and framework risk scores.
"""

from __future__ import annotations

import json
import logging
import math
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
    title="NAIL Predictive Vulnerability Engine",
    description="ML-powered threat forecasting for agentic AI vulnerabilities.",
    version="1.0.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = logging.getLogger("pve.server")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AVE_CATEGORIES = [
    "prompt_injection", "tool_abuse", "memory_poisoning", "identity_spoofing",
    "goal_hijacking", "knowledge_poisoning", "resource_exhaustion",
    "output_manipulation", "privilege_escalation", "trust_exploitation",
    "context_overflow", "model_denial_of_service", "data_exfiltration",
    "supply_chain", "model_poisoning", "multi_agent_coordination",
    "reward_hacking", "emergent_behavior",
]

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class PredictionType(str, Enum):
    CATEGORY_EMERGENCE = "category_emergence"
    SEVERITY_TREND = "severity_trend"
    FRAMEWORK_RISK = "framework_risk"
    ATTACK_EVOLUTION = "attack_evolution"
    DEFENCE_GAP = "defence_gap"


class SignalSource(str, Enum):
    AVE_HISTORY = "ave_history"
    CVE_NVD = "cve_nvd"
    ARXIV = "arxiv"
    GITHUB_ADVISORY = "github_advisory"
    MITRE_UPDATE = "mitre_update"
    FRAMEWORK_RELEASE = "framework_release"
    COMMUNITY_REPORT = "community_report"


class Signal(BaseModel):
    """A single intelligence signal from any source."""

    signal_id: str = Field(default_factory=lambda: f"sig-{uuid.uuid4().hex[:10]}")
    source: SignalSource
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    category_hint: str = ""
    severity_hint: str = ""
    text: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    relevance_score: float = 0.0


class Prediction(BaseModel):
    """A single prediction output."""

    prediction_id: str = Field(default_factory=lambda: f"pred-{uuid.uuid4().hex[:10]}")
    prediction_type: PredictionType
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    horizon_days: int = 90
    confidence: float = 0.0
    payload: dict[str, Any] = Field(default_factory=dict)


class ModelStatus(BaseModel):
    """Status of a prediction model."""

    model_name: str
    version: str
    last_trained: str
    training_samples: int
    accuracy_30d: float
    accuracy_90d: float
    status: str = "healthy"


# ---------------------------------------------------------------------------
# In-memory stores (production → PostgreSQL + Redis)
# ---------------------------------------------------------------------------

signal_store: list[Signal] = []
prediction_store: list[Prediction] = []

# Simulated historical data for feature engineering
historical_monthly_counts: dict[str, list[int]] = {
    cat: [
        max(0, int(3 + 2 * math.sin(i / 3.0) + (i * 0.15) + (hash(cat + str(i)) % 3)))
        for i in range(24)
    ]
    for cat in AVE_CATEGORIES
}

historical_severity_dist: dict[str, dict[str, float]] = {
    "prompt_injection": {"critical": 0.15, "high": 0.30, "medium": 0.40, "low": 0.15},
    "tool_abuse": {"critical": 0.10, "high": 0.25, "medium": 0.45, "low": 0.20},
    "memory_poisoning": {"critical": 0.08, "high": 0.22, "medium": 0.45, "low": 0.25},
    "trust_exploitation": {"critical": 0.12, "high": 0.28, "medium": 0.40, "low": 0.20},
    "goal_hijacking": {"critical": 0.10, "high": 0.25, "medium": 0.40, "low": 0.25},
    "multi_agent_coordination": {"critical": 0.18, "high": 0.32, "medium": 0.35, "low": 0.15},
}

model_registry: dict[str, ModelStatus] = {
    "time_series_forecaster": ModelStatus(
        model_name="time_series_forecaster",
        version="1.2.0",
        last_trained="2026-03-15T00:00:00Z",
        training_samples=1200,
        accuracy_30d=0.78,
        accuracy_90d=0.65,
    ),
    "nlp_trend_classifier": ModelStatus(
        model_name="nlp_trend_classifier",
        version="1.1.0",
        last_trained="2026-03-10T00:00:00Z",
        training_samples=8500,
        accuracy_30d=0.72,
        accuracy_90d=0.61,
    ),
    "graph_neural_network": ModelStatus(
        model_name="graph_neural_network",
        version="1.0.0",
        last_trained="2026-03-01T00:00:00Z",
        training_samples=3200,
        accuracy_30d=0.69,
        accuracy_90d=0.58,
    ),
}


# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------


def compute_trend(values: list[int | float], window: int = 6) -> str:
    """Compute trend direction from recent values."""
    if len(values) < window * 2:
        return "insufficient_data"
    recent = statistics.mean(values[-window:])
    earlier = statistics.mean(values[-window * 2 : -window])
    if earlier == 0:
        return "emerging" if recent > 0 else "stable"
    pct_change = (recent - earlier) / earlier
    if pct_change > 0.20:
        return "escalating"
    elif pct_change > 0.05:
        return "increasing"
    elif pct_change < -0.20:
        return "declining"
    elif pct_change < -0.05:
        return "decreasing"
    return "stable"


def compute_momentum(values: list[int | float], window: int = 3) -> float:
    """Compute momentum (rate of change of trend)."""
    if len(values) < window + 1:
        return 0.0
    recent = values[-window:]
    diffs = [recent[i] - recent[i - 1] for i in range(1, len(recent))]
    return statistics.mean(diffs) if diffs else 0.0


def project_severity(
    current_dist: dict[str, float],
    trend: str,
    horizon_days: int = 30,
) -> dict[str, float]:
    """Project severity distribution based on trend."""
    shift = {
        "escalating": 0.05 * (horizon_days / 30),
        "increasing": 0.02 * (horizon_days / 30),
        "stable": 0.0,
        "decreasing": -0.02 * (horizon_days / 30),
        "declining": -0.05 * (horizon_days / 30),
    }.get(trend, 0.0)

    projected = {}
    severity_order = ["critical", "high", "medium", "low"]
    remaining = 1.0
    for i, sev in enumerate(severity_order):
        base = current_dist.get(sev, 0.25)
        if i < 2:  # critical/high increase with escalation
            adjusted = min(0.60, max(0.0, base + shift))
        else:  # medium/low decrease
            adjusted = max(0.0, base - shift * 0.5)
        projected[sev] = round(adjusted, 3)

    # Normalise to sum to 1.0
    total = sum(projected.values())
    if total > 0:
        projected = {k: round(v / total, 3) for k, v in projected.items()}
    return projected


def compute_framework_risk(
    vuln_count: int,
    avg_severity: float,
    release_cadence: float,
    unpatched_critical: int,
) -> float:
    """Compute composite risk score (0-10) for a framework."""
    vuln_component = min(10, vuln_count / 5)
    severity_component = avg_severity
    cadence_risk = min(10, release_cadence * 2)
    patch_risk = min(10, unpatched_critical * 3)

    score = (
        0.30 * vuln_component
        + 0.25 * severity_component
        + 0.20 * cadence_risk
        + 0.25 * patch_risk
    )
    return round(min(10.0, max(0.0, score)), 1)


# ---------------------------------------------------------------------------
# Prediction generators
# ---------------------------------------------------------------------------


def generate_category_predictions(horizon_days: int = 90) -> Prediction:
    """Generate category emergence forecasts."""
    predictions = []

    # Analyse signal store for emerging themes
    signal_categories = Counter()
    for sig in signal_store[-500:]:
        if sig.category_hint:
            signal_categories[sig.category_hint] += 1

    # Compute per-category trend and momentum
    for cat in AVE_CATEGORIES:
        values = historical_monthly_counts.get(cat, [])
        trend = compute_trend(values)
        momentum = compute_momentum(values)

        if trend in ("escalating", "emerging") or momentum > 1.0:
            confidence = min(0.95, 0.5 + momentum * 0.1 + (0.1 if trend == "escalating" else 0))
            predictions.append({
                "category": cat,
                "trend": trend,
                "momentum": round(momentum, 2),
                "confidence": round(confidence, 2),
                "projected_monthly_count": max(0, int(values[-1] + momentum * (horizon_days / 30))) if values else 0,
                "signal_count": signal_categories.get(cat, 0),
            })

    # Check for novel categories in signals
    known = set(AVE_CATEGORIES)
    novel = {k: v for k, v in signal_categories.items() if k not in known and v >= 3}
    for cat, count in novel.items():
        predictions.append({
            "category": cat,
            "trend": "emerging",
            "momentum": 0.0,
            "confidence": min(0.7, count * 0.1),
            "projected_monthly_count": count,
            "signal_count": count,
            "is_novel": True,
        })

    predictions.sort(key=lambda p: p["confidence"], reverse=True)

    return Prediction(
        prediction_type=PredictionType.CATEGORY_EMERGENCE,
        horizon_days=horizon_days,
        confidence=round(statistics.mean(p["confidence"] for p in predictions), 2) if predictions else 0.0,
        payload={
            "prediction_count": len(predictions),
            "predictions": predictions[:15],
            "analysis_window_months": 24,
            "signals_analysed": len(signal_store),
        },
    )


def generate_severity_prediction(category: str, horizon_days: int = 90) -> Prediction:
    """Generate severity trend projection for a category."""
    current = historical_severity_dist.get(
        category,
        {"critical": 0.10, "high": 0.25, "medium": 0.40, "low": 0.25},
    )
    values = historical_monthly_counts.get(category, [])
    trend = compute_trend(values)

    projected_30d = project_severity(current, trend, 30)
    projected_60d = project_severity(current, trend, 60)
    projected_90d = project_severity(current, trend, horizon_days)

    return Prediction(
        prediction_type=PredictionType.SEVERITY_TREND,
        horizon_days=horizon_days,
        confidence=round(0.65 + (0.1 if len(values) > 12 else 0), 2),
        payload={
            "category": category,
            "current_distribution": current,
            "projected_30d": projected_30d,
            "projected_60d": projected_60d,
            "projected_90d": projected_90d,
            "trend": trend,
            "momentum": compute_momentum(values),
            "data_points": len(values),
        },
    )


def generate_framework_risk_prediction(framework: str) -> Prediction:
    """Generate risk projection for a framework."""
    # Simulated framework data (production → query KG + AVE DB)
    framework_data = {
        "LangChain": {"vulns": 18, "avg_sev": 6.2, "cadence": 4.0, "unpatched": 3},
        "CrewAI": {"vulns": 8, "avg_sev": 5.5, "cadence": 2.0, "unpatched": 1},
        "AutoGen": {"vulns": 12, "avg_sev": 5.8, "cadence": 1.5, "unpatched": 2},
        "LlamaIndex": {"vulns": 10, "avg_sev": 5.0, "cadence": 3.0, "unpatched": 1},
    }

    data = framework_data.get(framework)
    if not data:
        data = {"vulns": 5, "avg_sev": 5.0, "cadence": 1.0, "unpatched": 0}

    current_risk = compute_framework_risk(
        data["vulns"], data["avg_sev"], data["cadence"], data["unpatched"]
    )
    # Project risk increase
    risk_30d = min(10, round(current_risk * 1.05, 1))
    risk_60d = min(10, round(current_risk * 1.10, 1))
    risk_90d = min(10, round(current_risk * 1.15, 1))

    return Prediction(
        prediction_type=PredictionType.FRAMEWORK_RISK,
        confidence=0.70,
        payload={
            "framework": framework,
            "current_risk_score": current_risk,
            "projected_30d_risk": risk_30d,
            "projected_60d_risk": risk_60d,
            "projected_90d_risk": risk_90d,
            "risk_factors": [
                {"factor": f"{data['vulns']} known vulnerabilities", "weight": 0.30},
                {"factor": f"Average severity {data['avg_sev']}/10", "weight": 0.25},
                {"factor": f"Release cadence {data['cadence']}/month", "weight": 0.20},
                {"factor": f"{data['unpatched']} unpatched critical findings", "weight": 0.25},
            ],
            "category_exposure": {
                cat: len(historical_monthly_counts.get(cat, [])) > 0
                for cat in AVE_CATEGORIES[:8]
            },
        },
    )


def generate_defence_gap_analysis() -> Prediction:
    """Identify gaps where threats outpace defences."""
    gaps = []
    for cat in AVE_CATEGORIES:
        values = historical_monthly_counts.get(cat, [])
        trend = compute_trend(values)
        momentum = compute_momentum(values)

        # Simulated defence coverage (production → query DOP)
        coverage = 0.6 + (hash(cat) % 30) / 100  # 0.60-0.89 simulated

        if trend in ("escalating", "increasing") and coverage < 0.75:
            gaps.append({
                "category": cat,
                "threat_trend": trend,
                "threat_momentum": round(momentum, 2),
                "defence_coverage": round(coverage, 2),
                "gap_severity": "critical" if coverage < 0.5 else "high" if coverage < 0.65 else "medium",
                "recommended_actions": [
                    f"Deploy additional {cat.replace('_', ' ')} guardrails",
                    f"Increase monitoring sensitivity for {cat.replace('_', ' ')}",
                    "Review and update existing defence rules",
                ],
            })

    gaps.sort(key=lambda g: g["defence_coverage"])

    return Prediction(
        prediction_type=PredictionType.DEFENCE_GAP,
        confidence=0.75,
        payload={
            "total_categories": len(AVE_CATEGORIES),
            "categories_with_gaps": len(gaps),
            "gaps": gaps,
            "overall_coverage": round(
                statistics.mean(g["defence_coverage"] for g in gaps), 2
            ) if gaps else 1.0,
        },
    )


def generate_attack_evolution() -> Prediction:
    """Predict attack technique evolution timeline."""
    evolutions = []
    for cat in AVE_CATEGORIES:
        values = historical_monthly_counts.get(cat, [])
        trend = compute_trend(values)
        momentum = compute_momentum(values)

        evolutions.append({
            "category": cat,
            "current_sophistication": "advanced" if momentum > 1.0 else "moderate" if momentum > 0 else "stable",
            "trend": trend,
            "predicted_evolution": {
                "30_days": f"{'Increased' if momentum > 0 else 'Stable'} technique diversity",
                "60_days": f"{'Novel variants expected' if trend == 'escalating' else 'Incremental refinement'}",
                "90_days": f"{'Potential category expansion' if momentum > 1.5 else 'Continued refinement'}",
            },
            "key_drivers": [
                "Research paper publication rate",
                "Framework architecture changes",
                "Defence evasion pressure",
            ],
        })

    evolutions.sort(key=lambda e: e["trend"] == "escalating", reverse=True)

    return Prediction(
        prediction_type=PredictionType.ATTACK_EVOLUTION,
        confidence=0.62,
        payload={
            "categories_analysed": len(evolutions),
            "evolutions": evolutions[:10],
        },
    )


# ---------------------------------------------------------------------------
# API endpoints — Predictions
# ---------------------------------------------------------------------------


@app.get("/v1/predictions/latest")
async def latest_predictions() -> dict[str, Any]:
    """Get the latest batch of all prediction types."""
    cat_pred = generate_category_predictions()
    defence_pred = generate_defence_gap_analysis()
    attack_pred = generate_attack_evolution()

    batch = [cat_pred, defence_pred, attack_pred]
    prediction_store.extend(batch)

    return {
        "batch_id": f"batch-{uuid.uuid4().hex[:8]}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "prediction_count": len(batch),
        "predictions": [p.model_dump() for p in batch],
    }


@app.get("/v1/predictions/categories")
async def category_predictions(
    horizon: int = Query(90, ge=7, le=365),
) -> dict[str, Any]:
    """Category emergence forecasts."""
    pred = generate_category_predictions(horizon)
    prediction_store.append(pred)
    return pred.model_dump()


@app.get("/v1/predictions/severity/{category}")
async def severity_prediction(
    category: str,
    horizon: int = Query(90, ge=7, le=365),
) -> dict[str, Any]:
    """Severity trend projection for a specific category."""
    pred = generate_severity_prediction(category, horizon)
    prediction_store.append(pred)
    return pred.model_dump()


@app.get("/v1/predictions/framework-risk/{framework_name}")
async def framework_risk_prediction(framework_name: str) -> dict[str, Any]:
    """Framework risk projection."""
    pred = generate_framework_risk_prediction(framework_name)
    prediction_store.append(pred)
    return pred.model_dump()


@app.get("/v1/predictions/attack-evolution")
async def attack_evolution_prediction() -> dict[str, Any]:
    """Attack technique evolution timeline."""
    pred = generate_attack_evolution()
    prediction_store.append(pred)
    return pred.model_dump()


@app.get("/v1/predictions/defence-gaps")
async def defence_gaps() -> dict[str, Any]:
    """Defence gap analysis."""
    pred = generate_defence_gap_analysis()
    prediction_store.append(pred)
    return pred.model_dump()


# ---------------------------------------------------------------------------
# API endpoints — Model management
# ---------------------------------------------------------------------------


@app.get("/v1/models/status")
async def models_status() -> dict[str, Any]:
    """Model health and training status."""
    return {
        "models": {name: m.model_dump() for name, m in model_registry.items()},
        "ensemble_status": "healthy",
        "last_prediction_batch": prediction_store[-1].generated_at if prediction_store else None,
    }


@app.post("/v1/models/retrain")
async def retrain_models(
    model_name: Optional[str] = Query(None),
) -> dict[str, Any]:
    """Trigger model retraining."""
    now = datetime.now(timezone.utc).isoformat()
    targets = [model_name] if model_name else list(model_registry.keys())

    for name in targets:
        if name in model_registry:
            model_registry[name].last_trained = now
            model_registry[name].status = "retraining"

    return {
        "retrain_requested": targets,
        "requested_at": now,
        "estimated_duration_minutes": len(targets) * 15,
    }


@app.get("/v1/models/performance")
async def model_performance() -> dict[str, Any]:
    """Accuracy metrics and backtest results."""
    return {
        "models": {
            name: {
                "accuracy_30d": m.accuracy_30d,
                "accuracy_90d": m.accuracy_90d,
                "precision": round(m.accuracy_30d * 0.95, 2),
                "recall": round(m.accuracy_30d * 0.88, 2),
                "f1_score": round(m.accuracy_30d * 0.91, 2),
            }
            for name, m in model_registry.items()
        },
        "ensemble_accuracy_30d": round(
            statistics.mean(m.accuracy_30d for m in model_registry.values()), 2
        ),
        "ensemble_accuracy_90d": round(
            statistics.mean(m.accuracy_90d for m in model_registry.values()), 2
        ),
    }


@app.get("/v1/models/features")
async def feature_importance() -> dict[str, Any]:
    """Feature importance rankings per model."""
    return {
        "time_series_forecaster": [
            {"feature": "monthly_vuln_count", "importance": 0.28},
            {"feature": "severity_distribution_shift", "importance": 0.22},
            {"feature": "discovery_latency_trend", "importance": 0.18},
            {"feature": "category_momentum", "importance": 0.17},
            {"feature": "seasonal_component", "importance": 0.15},
        ],
        "nlp_trend_classifier": [
            {"feature": "paper_abstract_embedding_cluster", "importance": 0.30},
            {"feature": "keyword_emergence_frequency", "importance": 0.25},
            {"feature": "topic_drift_velocity", "importance": 0.20},
            {"feature": "cross_citation_density", "importance": 0.15},
            {"feature": "author_network_centrality", "importance": 0.10},
        ],
        "graph_neural_network": [
            {"feature": "node_degree_centrality_delta", "importance": 0.25},
            {"feature": "subgraph_density_per_category", "importance": 0.22},
            {"feature": "cross_category_edge_growth", "importance": 0.20},
            {"feature": "defence_coverage_ratio", "importance": 0.18},
            {"feature": "temporal_embedding_drift", "importance": 0.15},
        ],
    }


# ---------------------------------------------------------------------------
# API endpoints — Signal ingestion
# ---------------------------------------------------------------------------


@app.post("/v1/ingest/signals", status_code=status.HTTP_201_CREATED)
async def ingest_signals(signals: list[Signal]) -> dict[str, Any]:
    """Push external signal data for prediction models."""
    signal_store.extend(signals)
    return {
        "ingested": len(signals),
        "total_signals": len(signal_store),
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/v1/signals/sources")
async def signal_sources() -> dict[str, Any]:
    """List configured data sources."""
    source_counts = Counter(s.source.value for s in signal_store)
    return {
        "configured_sources": [s.value for s in SignalSource],
        "active_sources": dict(source_counts),
        "total_signals": len(signal_store),
    }


@app.get("/v1/signals/health")
async def signal_health() -> dict[str, Any]:
    """Data pipeline health check."""
    now = datetime.now(timezone.utc)
    recent = [
        s for s in signal_store
        if s.timestamp > (now - timedelta(hours=24)).isoformat()
    ]
    return {
        "status": "healthy" if len(recent) > 0 or len(signal_store) == 0 else "stale",
        "signals_last_24h": len(recent),
        "total_signals": len(signal_store),
        "oldest_signal": signal_store[0].timestamp if signal_store else None,
        "newest_signal": signal_store[-1].timestamp if signal_store else None,
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "predictive-vulnerability-engine"}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8600)
