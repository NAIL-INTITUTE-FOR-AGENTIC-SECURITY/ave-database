"""
Civilisational Risk Dashboard — Core risk aggregation server.

Macro-scale risk aggregation engine drawing signals from all NAIL
subsystems to compute civilisational-level AI safety risk indices.
Tracks risk across 8 economic sectors and 6 geographic regions,
monitors 6 systemic risk indicators, provides 4-tier early warnings,
runs what-if scenarios, and generates policy recommendations with
regulatory citations plus executive briefings.
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
    title="NAIL Civilisational Risk Dashboard",
    description=(
        "Macro-scale risk aggregation — sector/region indices, systemic "
        "indicators, early warning, scenario modelling, and policy recommendations."
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

SECTORS = [
    "finance", "healthcare", "defence", "critical_infrastructure",
    "education", "government", "transportation", "energy",
]

REGIONS = ["NA", "EU", "UK", "APAC", "LATAM", "MEA"]


class WarningTier(str, Enum):
    ADVISORY = "advisory"
    ELEVATED = "elevated"
    SEVERE = "severe"
    CRITICAL = "critical"


class TrendDirection(str, Enum):
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    RAPIDLY_DEGRADING = "rapidly_degrading"


class IndicatorName(str, Enum):
    ATTACK_VELOCITY = "attack_velocity"
    DEFENCE_GAP = "defence_gap"
    COORDINATION_LEVEL = "coordination_level"
    NOVEL_THREAT_RATE = "novel_threat_rate"
    CASCADING_FAILURE_PROBABILITY = "cascading_failure_probability"
    RECOVERY_CAPACITY = "recovery_capacity"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class RiskSignal(BaseModel):
    id: str = Field(default_factory=lambda: f"SIG-{uuid.uuid4().hex[:8].upper()}")
    source_subsystem: str = ""
    sector: str = ""
    region: str = ""
    category: str = ""
    severity: float = Field(0.5, ge=0.0, le=1.0)
    description: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SignalCreate(BaseModel):
    source_subsystem: str = ""
    sector: str = ""
    region: str = ""
    category: str = ""
    severity: float = Field(0.5, ge=0.0, le=1.0)
    description: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskIndex(BaseModel):
    name: str
    score: float = Field(0.0, ge=0.0, le=1.0)
    signal_count: int = 0
    top_categories: list[dict[str, Any]] = Field(default_factory=list)
    warning_tier: WarningTier = WarningTier.ADVISORY
    last_updated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SystemicIndicator(BaseModel):
    name: IndicatorName
    value: float = Field(0.0, ge=0.0, le=1.0)
    trend: TrendDirection = TrendDirection.STABLE
    description: str = ""
    last_updated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class Warning(BaseModel):
    id: str = Field(default_factory=lambda: f"WARN-{uuid.uuid4().hex[:8].upper()}")
    tier: WarningTier
    sector: str = ""
    region: str = ""
    indicator: str = ""
    description: str = ""
    recommended_actions: list[str] = Field(default_factory=list)
    active: bool = True
    issued_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ScenarioRequest(BaseModel):
    name: str = "Custom Scenario"
    description: str = ""
    sector_impacts: dict[str, float] = Field(default_factory=dict)  # sector → impact delta
    region_impacts: dict[str, float] = Field(default_factory=dict)  # region → impact delta
    indicator_adjustments: dict[str, float] = Field(default_factory=dict)


class PolicyRecommendation(BaseModel):
    id: str = Field(default_factory=lambda: f"POL-{uuid.uuid4().hex[:8].upper()}")
    sector: str = ""
    region: str = ""
    risk_level: str = ""
    recommendation: str = ""
    regulatory_citations: list[str] = Field(default_factory=list)
    priority: int = Field(1, ge=1, le=5)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → InfluxDB + PostgreSQL + Redis)
# ---------------------------------------------------------------------------

SIGNALS: list[RiskSignal] = []
SECTOR_INDICES: dict[str, RiskIndex] = {}
REGION_INDICES: dict[str, RiskIndex] = {}
INDICATORS: dict[IndicatorName, SystemicIndicator] = {}
WARNINGS: list[Warning] = []
SCENARIOS: list[dict[str, Any]] = []
RECOMMENDATIONS: list[PolicyRecommendation] = []

# Warning tier thresholds
TIER_THRESHOLDS = {
    WarningTier.ADVISORY: 0.25,
    WarningTier.ELEVATED: 0.50,
    WarningTier.SEVERE: 0.70,
    WarningTier.CRITICAL: 0.85,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731
_rng = random.Random(42)


def _classify_warning(score: float) -> WarningTier:
    if score >= TIER_THRESHOLDS[WarningTier.CRITICAL]:
        return WarningTier.CRITICAL
    elif score >= TIER_THRESHOLDS[WarningTier.SEVERE]:
        return WarningTier.SEVERE
    elif score >= TIER_THRESHOLDS[WarningTier.ELEVATED]:
        return WarningTier.ELEVATED
    return WarningTier.ADVISORY


def _recalculate_indices() -> None:
    """Recalculate all sector and region risk indices from signals."""
    # Sector indices
    for sector in SECTORS:
        sector_signals = [s for s in SIGNALS if s.sector == sector]
        if not sector_signals:
            SECTOR_INDICES[sector] = RiskIndex(name=sector)
            continue

        avg_severity = statistics.mean(s.severity for s in sector_signals)
        cat_counts = Counter(s.category for s in sector_signals if s.category)
        top_cats = [{"category": c, "count": n} for c, n in cat_counts.most_common(5)]

        SECTOR_INDICES[sector] = RiskIndex(
            name=sector,
            score=round(avg_severity, 4),
            signal_count=len(sector_signals),
            top_categories=top_cats,
            warning_tier=_classify_warning(avg_severity),
        )

    # Region indices
    for region in REGIONS:
        region_signals = [s for s in SIGNALS if s.region == region]
        if not region_signals:
            REGION_INDICES[region] = RiskIndex(name=region)
            continue

        avg_severity = statistics.mean(s.severity for s in region_signals)
        cat_counts = Counter(s.category for s in region_signals if s.category)
        top_cats = [{"category": c, "count": n} for c, n in cat_counts.most_common(5)]

        REGION_INDICES[region] = RiskIndex(
            name=region,
            score=round(avg_severity, 4),
            signal_count=len(region_signals),
            top_categories=top_cats,
            warning_tier=_classify_warning(avg_severity),
        )


def _recalculate_indicators() -> None:
    """Compute 6 systemic risk indicators from signals."""
    if not SIGNALS:
        return

    recent = SIGNALS[-200:]  # Last 200 signals
    severities = [s.severity for s in recent]

    # Attack velocity: rate of high-severity signals
    high_sev = sum(1 for s in recent if s.severity > 0.7)
    attack_velocity = min(1.0, high_sev / max(len(recent), 1) * 3)

    # Defence gap: average severity (higher = bigger gap)
    defence_gap = statistics.mean(severities) if severities else 0.5

    # Coordination level: signals from multiple regions/sectors close in time
    unique_regions = len(set(s.region for s in recent if s.region))
    unique_sectors = len(set(s.sector for s in recent if s.sector))
    coordination = min(1.0, (unique_regions * unique_sectors) / (len(REGIONS) * len(SECTORS)))

    # Novel threat rate: unique categories / total categories
    unique_cats = len(set(s.category for s in recent if s.category))
    novel_rate = min(1.0, unique_cats / max(len(AVE_CATEGORIES), 1))

    # Cascading failure probability: based on cross-sector signals
    cross_sector = defaultdict(set)
    for s in recent:
        if s.sector and s.category:
            cross_sector[s.category].add(s.sector)
    multi_sector_cats = sum(1 for sectors in cross_sector.values() if len(sectors) > 2)
    cascading_prob = min(1.0, multi_sector_cats / max(len(AVE_CATEGORIES), 1) * 2)

    # Recovery capacity: inverse of severity trend (lower avg sev = better recovery)
    recovery = max(0.0, 1.0 - defence_gap)

    indicator_values = {
        IndicatorName.ATTACK_VELOCITY: (attack_velocity, "Rate of high-severity security events normalised against baseline"),
        IndicatorName.DEFENCE_GAP: (defence_gap, "Gap between detected threats and effective defences"),
        IndicatorName.COORDINATION_LEVEL: (coordination, "Degree of coordinated attacks across sectors/regions"),
        IndicatorName.NOVEL_THREAT_RATE: (novel_rate, "Rate of previously unseen vulnerability categories"),
        IndicatorName.CASCADING_FAILURE_PROBABILITY: (cascading_prob, "Probability of cross-sector cascading failures"),
        IndicatorName.RECOVERY_CAPACITY: (recovery, "System-wide capacity to recover from attacks"),
    }

    for name, (value, desc) in indicator_values.items():
        # Simple trend: compare to previous value
        prev = INDICATORS.get(name)
        if prev:
            delta = value - prev.value
            if delta > 0.05:
                trend = TrendDirection.RAPIDLY_DEGRADING if name != IndicatorName.RECOVERY_CAPACITY else TrendDirection.IMPROVING
            elif delta > 0.01:
                trend = TrendDirection.DEGRADING if name != IndicatorName.RECOVERY_CAPACITY else TrendDirection.IMPROVING
            elif delta < -0.05:
                trend = TrendDirection.IMPROVING if name != IndicatorName.RECOVERY_CAPACITY else TrendDirection.RAPIDLY_DEGRADING
            elif delta < -0.01:
                trend = TrendDirection.IMPROVING if name != IndicatorName.RECOVERY_CAPACITY else TrendDirection.DEGRADING
            else:
                trend = TrendDirection.STABLE
        else:
            trend = TrendDirection.STABLE

        INDICATORS[name] = SystemicIndicator(
            name=name,
            value=round(value, 4),
            trend=trend,
            description=desc,
        )


def _evaluate_warnings() -> list[Warning]:
    """Generate warnings based on current indices and indicators."""
    new_warnings: list[Warning] = []

    # Sector warnings
    for sector, idx in SECTOR_INDICES.items():
        if idx.warning_tier in (WarningTier.SEVERE, WarningTier.CRITICAL):
            w = Warning(
                tier=idx.warning_tier,
                sector=sector,
                description=f"Sector '{sector}' risk score {idx.score:.2f} "
                            f"exceeds {idx.warning_tier.value} threshold.",
                recommended_actions=[
                    f"Activate {sector} sector incident response protocols",
                    f"Notify {sector} regulatory bodies",
                    "Escalate to NAIL executive board",
                ],
            )
            new_warnings.append(w)
            WARNINGS.append(w)

    # Region warnings
    for region, idx in REGION_INDICES.items():
        if idx.warning_tier in (WarningTier.SEVERE, WarningTier.CRITICAL):
            w = Warning(
                tier=idx.warning_tier,
                region=region,
                description=f"Region '{region}' risk score {idx.score:.2f} "
                            f"exceeds {idx.warning_tier.value} threshold.",
                recommended_actions=[
                    f"Alert {region} regional response teams",
                    "Coordinate with cross-border intelligence sharing",
                ],
            )
            new_warnings.append(w)
            WARNINGS.append(w)

    # Indicator warnings
    for name, indicator in INDICATORS.items():
        if name == IndicatorName.RECOVERY_CAPACITY:
            if indicator.value < 0.3:
                w = Warning(
                    tier=WarningTier.CRITICAL,
                    indicator=name.value,
                    description=f"Recovery capacity critically low at {indicator.value:.2f}.",
                    recommended_actions=[
                        "Deploy emergency resilience measures",
                        "Activate backup defence systems",
                    ],
                )
                new_warnings.append(w)
                WARNINGS.append(w)
        elif indicator.value > 0.75:
            w = Warning(
                tier=WarningTier.SEVERE,
                indicator=name.value,
                description=f"Indicator '{name.value}' at {indicator.value:.2f} — exceeds severe threshold.",
                recommended_actions=[
                    f"Investigate {name.value} drivers",
                    "Brief executive leadership",
                ],
            )
            new_warnings.append(w)
            WARNINGS.append(w)

    return new_warnings


def _run_scenario(request: ScenarioRequest) -> dict[str, Any]:
    """What-if scenario modelling."""
    scenario_sectors: dict[str, float] = {}
    scenario_regions: dict[str, float] = {}

    # Apply sector impacts
    for sector in SECTORS:
        base = SECTOR_INDICES.get(sector, RiskIndex(name=sector)).score
        delta = request.sector_impacts.get(sector, 0.0)
        scenario_sectors[sector] = round(max(0.0, min(1.0, base + delta)), 4)

    # Apply region impacts
    for region in REGIONS:
        base = REGION_INDICES.get(region, RiskIndex(name=region)).score
        delta = request.region_impacts.get(region, 0.0)
        scenario_regions[region] = round(max(0.0, min(1.0, base + delta)), 4)

    # Adjusted indicators
    scenario_indicators: dict[str, float] = {}
    for name, indicator in INDICATORS.items():
        adj = request.indicator_adjustments.get(name.value, 0.0)
        scenario_indicators[name.value] = round(max(0.0, min(1.0, indicator.value + adj)), 4)

    # Compute aggregate risk
    all_scores = list(scenario_sectors.values()) + list(scenario_regions.values()) + list(scenario_indicators.values())
    aggregate = round(statistics.mean(all_scores), 4) if all_scores else 0.5

    result = {
        "scenario_name": request.name,
        "description": request.description,
        "sector_risk": scenario_sectors,
        "region_risk": scenario_regions,
        "indicator_risk": scenario_indicators,
        "aggregate_risk": aggregate,
        "aggregate_tier": _classify_warning(aggregate).value,
        "worst_sector": max(scenario_sectors, key=scenario_sectors.get) if scenario_sectors else "",
        "worst_region": max(scenario_regions, key=scenario_regions.get) if scenario_regions else "",
        "modelled_at": _now().isoformat(),
    }
    SCENARIOS.append(result)

    return result


def _generate_policy_recommendations() -> list[PolicyRecommendation]:
    """Generate policy recommendations from current risk state."""
    recs: list[PolicyRecommendation] = []

    regulatory_map = {
        "finance": ["Basel III AI Annex", "SEC ML Guidelines", "EU AI Act Art. 6"],
        "healthcare": ["EU AI Act Art. 6 (High-Risk)", "HIPAA AI Supplement", "FDA AI/ML SaMD"],
        "defence": ["NATO AI Strategy", "DoD Directive 3000.09", "EU AI Act Art. 5"],
        "critical_infrastructure": ["NIS2 Directive", "NIST AI RMF", "EU AI Act Art. 6"],
        "education": ["EU AI Act Art. 6", "FERPA AI Guidelines", "UNESCO AI Ethics"],
        "government": ["EU AI Act Art. 6", "OMB AI Memoranda", "UK AI Safety Institute"],
        "transportation": ["EU AI Act Art. 6", "FAA AI Policy", "EASA AI Roadmap"],
        "energy": ["NIS2 Directive", "NERC CIP AI", "EU AI Act Art. 6"],
    }

    for sector, idx in SECTOR_INDICES.items():
        if idx.score > 0.5:
            priority = 1 if idx.score > 0.8 else 2 if idx.score > 0.65 else 3
            citations = regulatory_map.get(sector, ["EU AI Act"])

            rec = PolicyRecommendation(
                sector=sector,
                risk_level=idx.warning_tier.value,
                recommendation=f"Sector '{sector}' risk at {idx.score:.2f}. "
                               f"Recommend immediate review of AI deployment policies, "
                               f"enhanced monitoring, and stakeholder notification.",
                regulatory_citations=citations,
                priority=priority,
            )
            recs.append(rec)
            RECOMMENDATIONS.append(rec)

    for region, idx in REGION_INDICES.items():
        if idx.score > 0.6:
            rec = PolicyRecommendation(
                region=region,
                risk_level=idx.warning_tier.value,
                recommendation=f"Region '{region}' risk at {idx.score:.2f}. "
                               f"Recommend cross-border intelligence coordination "
                               f"and regional regulatory alignment.",
                regulatory_citations=["EU AI Act", "OECD AI Principles", "G7 AI Code of Conduct"],
                priority=2,
            )
            recs.append(rec)
            RECOMMENDATIONS.append(rec)

    return recs


def _generate_briefing() -> dict[str, Any]:
    """Auto-generate executive briefing."""
    # Aggregate scores
    sector_scores = {s: idx.score for s, idx in SECTOR_INDICES.items()}
    region_scores = {r: idx.score for r, idx in REGION_INDICES.items()}
    indicator_vals = {n.value: i.value for n, i in INDICATORS.items()}

    overall = statistics.mean(
        list(sector_scores.values()) + list(region_scores.values()) + list(indicator_vals.values())
    ) if (sector_scores or region_scores or indicator_vals) else 0.5

    # Top risks
    top_sectors = sorted(sector_scores.items(), key=lambda x: x[1], reverse=True)[:3]
    top_regions = sorted(region_scores.items(), key=lambda x: x[1], reverse=True)[:3]
    critical_indicators = [
        (n, v) for n, v in indicator_vals.items() if v > 0.6
    ]

    active_warnings = [w for w in WARNINGS if w.active]

    return {
        "title": "NAIL Civilisational Risk — Executive Briefing",
        "generated_at": _now().isoformat(),
        "overall_risk_score": round(overall, 4),
        "overall_tier": _classify_warning(overall).value,
        "summary": f"Overall civilisational AI risk stands at {overall:.2%}. "
                   f"{len(active_warnings)} active warnings across "
                   f"{len(set(w.sector for w in active_warnings if w.sector))} sectors and "
                   f"{len(set(w.region for w in active_warnings if w.region))} regions.",
        "highest_risk_sectors": [{"sector": s, "score": sc} for s, sc in top_sectors],
        "highest_risk_regions": [{"region": r, "score": sc} for r, sc in top_regions],
        "critical_indicators": [{"indicator": n, "value": v} for n, v in critical_indicators],
        "active_warnings": len(active_warnings),
        "warning_breakdown": Counter(w.tier.value for w in active_warnings),
        "recent_policy_recommendations": len(RECOMMENDATIONS),
        "scenarios_modelled": len(SCENARIOS),
    }


def _compute_trends(days: int = 30) -> list[dict[str, Any]]:
    """Compute trend analysis for sectors/regions."""
    cutoff = (_now() - timedelta(days=days)).isoformat()
    recent = [s for s in SIGNALS if s.timestamp >= cutoff]

    trends: list[dict[str, Any]] = []

    for sector in SECTORS:
        sector_signals = [s for s in recent if s.sector == sector]
        if len(sector_signals) < 2:
            trends.append({"entity": sector, "type": "sector", "trend": "insufficient_data", "slope": 0.0})
            continue

        severities = [s.severity for s in sorted(sector_signals, key=lambda x: x.timestamp)]
        n = len(severities)
        x_mean = (n - 1) / 2
        y_mean = statistics.mean(severities)

        numerator = sum((i - x_mean) * (severities[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        slope = numerator / denominator if denominator else 0

        if slope > 0.005:
            direction = TrendDirection.RAPIDLY_DEGRADING if slope > 0.02 else TrendDirection.DEGRADING
        elif slope < -0.005:
            direction = TrendDirection.IMPROVING
        else:
            direction = TrendDirection.STABLE

        trends.append({
            "entity": sector,
            "type": "sector",
            "trend": direction.value,
            "slope": round(slope, 6),
            "observations": n,
            "mean_severity": round(y_mean, 4),
        })

    for region in REGIONS:
        region_signals = [s for s in recent if s.region == region]
        if len(region_signals) < 2:
            trends.append({"entity": region, "type": "region", "trend": "insufficient_data", "slope": 0.0})
            continue

        severities = [s.severity for s in sorted(region_signals, key=lambda x: x.timestamp)]
        n = len(severities)
        y_mean = statistics.mean(severities)
        x_mean = (n - 1) / 2

        numerator = sum((i - x_mean) * (severities[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        slope = numerator / denominator if denominator else 0

        if slope > 0.005:
            direction = TrendDirection.RAPIDLY_DEGRADING if slope > 0.02 else TrendDirection.DEGRADING
        elif slope < -0.005:
            direction = TrendDirection.IMPROVING
        else:
            direction = TrendDirection.STABLE

        trends.append({
            "entity": region,
            "type": "region",
            "trend": direction.value,
            "slope": round(slope, 6),
            "observations": n,
            "mean_severity": round(y_mean, 4),
        })

    return trends


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    rng = random.Random(42)
    base_time = _now() - timedelta(days=90)

    subsystems = [
        "threat-intel", "autonomous-redteam", "defence-mesh",
        "predictive-engine", "incident-commander", "adversarial-evolution",
    ]

    # Generate 500 signals across sectors, regions, categories
    for i in range(500):
        signal = RiskSignal(
            source_subsystem=rng.choice(subsystems),
            sector=rng.choice(SECTORS),
            region=rng.choice(REGIONS),
            category=rng.choice(AVE_CATEGORIES),
            severity=round(rng.uniform(0.1, 0.9), 4),
            description=f"Automated risk signal #{i + 1}",
            timestamp=(base_time + timedelta(hours=i * rng.uniform(1, 6))).isoformat(),
        )
        SIGNALS.append(signal)

    # Inject heightened risk for finance and defence
    for i in range(50):
        signal = RiskSignal(
            source_subsystem=rng.choice(subsystems),
            sector=rng.choice(["finance", "defence"]),
            region=rng.choice(REGIONS),
            category=rng.choice(["data_exfiltration", "supply_chain_compromise", "model_extraction"]),
            severity=round(rng.uniform(0.65, 0.95), 4),
            description=f"High-severity signal for critical sector #{i + 1}",
            timestamp=(base_time + timedelta(hours=i * rng.uniform(2, 8))).isoformat(),
        )
        SIGNALS.append(signal)

    # Calculate all indices
    _recalculate_indices()
    _recalculate_indicators()
    _evaluate_warnings()
    _generate_policy_recommendations()


_seed()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "civilisational-risk-dashboard",
        "version": "1.0.0",
        "signals": len(SIGNALS),
        "sectors_tracked": len(SECTORS),
        "regions_tracked": len(REGIONS),
        "active_warnings": sum(1 for w in WARNINGS if w.active),
    }


# ---- Signals ----------------------------------------------------------------

@app.post("/v1/signals", status_code=status.HTTP_201_CREATED)
async def ingest_signal(data: SignalCreate):
    if data.sector and data.sector not in SECTORS:
        raise HTTPException(400, f"Invalid sector: {data.sector}")
    if data.region and data.region not in REGIONS:
        raise HTTPException(400, f"Invalid region: {data.region}")
    if data.category and data.category not in AVE_CATEGORIES:
        raise HTTPException(400, f"Invalid category: {data.category}")

    signal = RiskSignal(
        source_subsystem=data.source_subsystem,
        sector=data.sector,
        region=data.region,
        category=data.category,
        severity=data.severity,
        description=data.description,
        metadata=data.metadata,
    )
    SIGNALS.append(signal)

    # Recalculate
    _recalculate_indices()
    _recalculate_indicators()

    return {"id": signal.id, "sector": signal.sector, "region": signal.region, "severity": signal.severity}


@app.get("/v1/signals")
async def query_signals(
    sector: Optional[str] = None,
    region: Optional[str] = None,
    category: Optional[str] = None,
    min_severity: Optional[float] = None,
    limit: int = Query(100, ge=1, le=1000),
):
    signals = list(SIGNALS)
    if sector:
        signals = [s for s in signals if s.sector == sector]
    if region:
        signals = [s for s in signals if s.region == region]
    if category:
        signals = [s for s in signals if s.category == category]
    if min_severity is not None:
        signals = [s for s in signals if s.severity >= min_severity]

    signals.sort(key=lambda s: s.timestamp, reverse=True)
    signals = signals[:limit]

    return {
        "count": len(signals),
        "signals": [
            {"id": s.id, "subsystem": s.source_subsystem, "sector": s.sector,
             "region": s.region, "category": s.category, "severity": s.severity,
             "timestamp": s.timestamp}
            for s in signals
        ],
    }


# ---- Indices ----------------------------------------------------------------

@app.get("/v1/indices")
async def all_indices():
    return {
        "sectors": {s: {"score": idx.score, "tier": idx.warning_tier.value, "signals": idx.signal_count}
                    for s, idx in SECTOR_INDICES.items()},
        "regions": {r: {"score": idx.score, "tier": idx.warning_tier.value, "signals": idx.signal_count}
                    for r, idx in REGION_INDICES.items()},
    }


@app.get("/v1/indices/{sector}")
async def sector_index(sector: str):
    if sector not in SECTOR_INDICES:
        raise HTTPException(404, f"Sector '{sector}' not found")
    idx = SECTOR_INDICES[sector]
    return {
        "sector": sector,
        "score": idx.score,
        "warning_tier": idx.warning_tier.value,
        "signal_count": idx.signal_count,
        "top_categories": idx.top_categories,
        "last_updated": idx.last_updated,
    }


# ---- Indicators -------------------------------------------------------------

@app.get("/v1/indicators")
async def get_indicators():
    return {
        "count": len(INDICATORS),
        "indicators": [
            {"name": i.name.value, "value": i.value, "trend": i.trend.value,
             "description": i.description, "last_updated": i.last_updated}
            for i in INDICATORS.values()
        ],
    }


# ---- Warnings ---------------------------------------------------------------

@app.get("/v1/warnings")
async def get_warnings(active_only: bool = True, tier: Optional[WarningTier] = None):
    warnings = list(WARNINGS)
    if active_only:
        warnings = [w for w in warnings if w.active]
    if tier:
        warnings = [w for w in warnings if w.tier == tier]

    return {
        "count": len(warnings),
        "warnings": [
            {"id": w.id, "tier": w.tier.value, "sector": w.sector, "region": w.region,
             "indicator": w.indicator, "description": w.description,
             "recommended_actions": w.recommended_actions, "issued_at": w.issued_at}
            for w in warnings
        ],
    }


@app.post("/v1/warnings/evaluate")
async def evaluate_warnings():
    new_warnings = _evaluate_warnings()
    return {
        "new_warnings": len(new_warnings),
        "total_active": sum(1 for w in WARNINGS if w.active),
        "warnings": [
            {"id": w.id, "tier": w.tier.value, "sector": w.sector, "region": w.region}
            for w in new_warnings
        ],
    }


# ---- Trends -----------------------------------------------------------------

@app.get("/v1/trends")
async def get_trends(days: int = Query(30, ge=7, le=365)):
    trends = _compute_trends(days)
    return {"period_days": days, "count": len(trends), "trends": trends}


# ---- Scenarios --------------------------------------------------------------

@app.post("/v1/scenarios/run")
async def run_scenario(request: ScenarioRequest):
    result = _run_scenario(request)
    return result


@app.get("/v1/scenarios")
async def list_scenarios():
    return {"count": len(SCENARIOS), "scenarios": SCENARIOS}


# ---- Policy Recommendations -------------------------------------------------

@app.post("/v1/policy/recommend")
async def generate_recommendations():
    recs = _generate_policy_recommendations()
    return {
        "generated": len(recs),
        "recommendations": [
            {"id": r.id, "sector": r.sector, "region": r.region,
             "risk_level": r.risk_level, "priority": r.priority,
             "recommendation": r.recommendation,
             "citations": r.regulatory_citations}
            for r in recs
        ],
    }


@app.get("/v1/policy/recommendations")
async def list_recommendations(sector: Optional[str] = None, region: Optional[str] = None):
    recs = list(RECOMMENDATIONS)
    if sector:
        recs = [r for r in recs if r.sector == sector]
    if region:
        recs = [r for r in recs if r.region == region]

    return {
        "count": len(recs),
        "recommendations": [
            {"id": r.id, "sector": r.sector, "region": r.region,
             "risk_level": r.risk_level, "priority": r.priority,
             "recommendation": r.recommendation,
             "citations": r.regulatory_citations}
            for r in recs
        ],
    }


# ---- Briefing ---------------------------------------------------------------

@app.get("/v1/briefing")
async def executive_briefing():
    return _generate_briefing()


# ---- Analytics --------------------------------------------------------------

@app.get("/v1/analytics")
async def risk_analytics():
    sector_scores = {s: idx.score for s, idx in SECTOR_INDICES.items()}
    region_scores = {r: idx.score for r, idx in REGION_INDICES.items()}

    overall = statistics.mean(
        list(sector_scores.values()) + list(region_scores.values())
    ) if (sector_scores or region_scores) else 0.5

    return {
        "total_signals": len(SIGNALS),
        "signals_by_sector": Counter(s.sector for s in SIGNALS if s.sector),
        "signals_by_region": Counter(s.region for s in SIGNALS if s.region),
        "signals_by_category": Counter(s.category for s in SIGNALS if s.category),
        "sector_scores": sector_scores,
        "region_scores": region_scores,
        "overall_risk": round(overall, 4),
        "overall_tier": _classify_warning(overall).value,
        "active_warnings": sum(1 for w in WARNINGS if w.active),
        "total_warnings_issued": len(WARNINGS),
        "scenarios_modelled": len(SCENARIOS),
        "policy_recommendations": len(RECOMMENDATIONS),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9103)
