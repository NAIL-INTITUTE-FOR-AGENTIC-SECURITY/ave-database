"""Resilience Scorecard — Phase 28 Service 4 · Port 9918"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random

app = FastAPI(title="Resilience Scorecard", version="0.28.4")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class ServiceType(str, Enum):
    api = "api"
    worker = "worker"
    database = "database"
    cache = "cache"
    gateway = "gateway"
    ml_service = "ml_service"

class Tier(str, Enum):
    platinum = "platinum"
    gold = "gold"
    silver = "silver"
    bronze = "bronze"

TIER_THRESHOLDS = {"platinum": 90, "gold": 75, "silver": 60, "bronze": 40}

class Dimension(str, Enum):
    availability = "availability"
    recoverability = "recoverability"
    scalability = "scalability"
    degradation_handling = "degradation_handling"

DIMENSION_WEIGHTS = {"availability": 0.35, "recoverability": 0.25, "scalability": 0.20, "degradation_handling": 0.20}

# ── Models ───────────────────────────────────────────────────────────
class ServiceCreate(BaseModel):
    name: str
    service_type: ServiceType
    tier: Tier = Tier.silver
    owner: str = ""

class MeasurementCreate(BaseModel):
    dimension: Dimension
    value: float = Field(75, ge=0, le=100)
    context: str = ""

# ── Stores ───────────────────────────────────────────────────────────
services: dict[str, dict] = {}

def _now():
    return datetime.now(timezone.utc).isoformat()

def _init_service(sid: str):
    s = services[sid]
    if "scores" not in s:
        s["scores"] = {d.value: [] for d in Dimension}
        s["history"] = []

def _current_scores(sid: str) -> dict:
    s = services[sid]
    _init_service(sid)
    result = {}
    for dim in Dimension:
        vals = s["scores"][dim.value]
        if vals:
            result[dim.value] = round(sum(v["value"] for v in vals[-10:]) / min(len(vals), 10), 1)
        else:
            result[dim.value] = 0
    return result

def _composite_score(dim_scores: dict) -> float:
    return round(sum(dim_scores.get(d.value, 0) * DIMENSION_WEIGHTS[d.value] for d in Dimension), 1)

def _trend(history: list[dict]) -> str:
    if len(history) < 2:
        return "insufficient_data"
    recent = history[-3:]
    older = history[-6:-3] if len(history) >= 6 else history[:3]
    avg_recent = sum(h["composite"] for h in recent) / len(recent)
    avg_older = sum(h["composite"] for h in older) / len(older)
    if avg_recent > avg_older + 2:
        return "improving"
    if avg_recent < avg_older - 2:
        return "declining"
    return "stable"

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "resilience-scorecard",
        "status": "healthy",
        "version": "0.28.4",
        "tracked_services": len(services),
    }

# ── Services ─────────────────────────────────────────────────────────
@app.post("/v1/services", status_code=201)
def create_service(body: ServiceCreate):
    sid = str(uuid.uuid4())
    rec = {"id": sid, **body.model_dump(), "created_at": _now()}
    services[sid] = rec
    _init_service(sid)
    return rec

@app.get("/v1/services")
def list_services(tier: Optional[Tier] = None, service_type: Optional[ServiceType] = None):
    out = list(services.values())
    if tier:
        out = [s for s in out if s["tier"] == tier]
    if service_type:
        out = [s for s in out if s["service_type"] == service_type]
    # Enrich with current scores
    enriched = []
    for s in out:
        _init_service(s["id"])
        dim_scores = _current_scores(s["id"])
        composite = _composite_score(dim_scores)
        enriched.append({**{k: v for k, v in s.items() if k not in ("scores", "history")}, "composite_score": composite, "dimension_scores": dim_scores})
    return sorted(enriched, key=lambda s: s["composite_score"], reverse=True)

@app.get("/v1/services/{sid}")
def get_service(sid: str):
    if sid not in services:
        raise HTTPException(404, "Service not found")
    _init_service(sid)
    s = services[sid]
    dim_scores = _current_scores(sid)
    composite = _composite_score(dim_scores)
    threshold = TIER_THRESHOLDS.get(s["tier"], 60)
    return {
        **{k: v for k, v in s.items() if k not in ("scores", "history")},
        "dimension_scores": dim_scores,
        "composite_score": composite,
        "tier_threshold": threshold,
        "meets_tier": composite >= threshold,
        "trend": _trend(s["history"]),
        "measurements_count": sum(len(s["scores"][d.value]) for d in Dimension),
    }

# ── Measurements ─────────────────────────────────────────────────────
@app.post("/v1/services/{sid}/measurements")
def record_measurement(sid: str, body: MeasurementCreate):
    if sid not in services:
        raise HTTPException(404, "Service not found")
    _init_service(sid)
    s = services[sid]
    entry = {"id": str(uuid.uuid4()), "value": body.value, "context": body.context, "recorded_at": _now()}
    s["scores"][body.dimension].append(entry)

    # Update history snapshot
    dim_scores = _current_scores(sid)
    composite = _composite_score(dim_scores)
    s["history"].append({"timestamp": _now(), "composite": composite, "dimensions": dim_scores.copy()})

    return {"measurement": entry, "current_composite": composite, "dimension_scores": dim_scores}

# ── History ──────────────────────────────────────────────────────────
@app.get("/v1/services/{sid}/history")
def get_history(sid: str, limit: int = Query(50, ge=1)):
    if sid not in services:
        raise HTTPException(404, "Service not found")
    _init_service(sid)
    return {"service_id": sid, "history": services[sid]["history"][-limit:], "trend": _trend(services[sid]["history"])}

# ── Gap Analysis ─────────────────────────────────────────────────────
@app.get("/v1/services/{sid}/gaps")
def gap_analysis(sid: str):
    if sid not in services:
        raise HTTPException(404, "Service not found")
    _init_service(sid)
    s = services[sid]
    dim_scores = _current_scores(sid)
    threshold = TIER_THRESHOLDS.get(s["tier"], 60)

    gaps = []
    recommendations = {
        "availability": "Improve health checks, add redundancy, increase monitoring coverage",
        "recoverability": "Reduce MTTR with runbooks, improve backup freshness, add automated recovery",
        "scalability": "Implement auto-scaling, increase capacity headroom, optimize resource usage",
        "degradation_handling": "Add circuit breakers, implement graceful degradation, create fallback paths",
    }

    for dim in Dimension:
        score = dim_scores[dim.value]
        weighted_threshold = threshold  # each dimension should meet tier threshold
        if score < weighted_threshold:
            gap = round(weighted_threshold - score, 1)
            gaps.append({
                "dimension": dim.value,
                "current_score": score,
                "target_score": weighted_threshold,
                "gap": gap,
                "priority": round(gap * DIMENSION_WEIGHTS[dim.value], 1),
                "recommendation": recommendations[dim.value],
            })

    return {"service_id": sid, "tier": s["tier"], "tier_threshold": threshold, "gaps": sorted(gaps, key=lambda g: g["priority"], reverse=True), "total_gap_score": round(sum(g["gap"] for g in gaps), 1)}

# ── Certification ────────────────────────────────────────────────────
@app.get("/v1/services/{sid}/certification")
def certification(sid: str):
    if sid not in services:
        raise HTTPException(404, "Service not found")
    _init_service(sid)
    s = services[sid]
    dim_scores = _current_scores(sid)
    composite = _composite_score(dim_scores)
    threshold = TIER_THRESHOLDS.get(s["tier"], 60)
    meets = composite >= threshold

    # Check if all dimensions meet threshold
    all_dimensions_pass = all(dim_scores[d.value] >= threshold for d in Dimension)

    # Consecutive days meeting (simulated from history length)
    consecutive = 0
    for h in reversed(s["history"]):
        if h["composite"] >= threshold:
            consecutive += 1
        else:
            break

    certified = meets and all_dimensions_pass and consecutive >= 5  # 5 snapshots ≈ sustained

    return {
        "service_id": sid,
        "tier": s["tier"],
        "composite_score": composite,
        "threshold": threshold,
        "meets_threshold": meets,
        "all_dimensions_pass": all_dimensions_pass,
        "consecutive_passing_snapshots": consecutive,
        "certified": certified,
        "certification_status": "certified" if certified else "not_certified",
    }

# ── Benchmarks ───────────────────────────────────────────────────────
@app.get("/v1/benchmarks")
def benchmarks():
    if not services:
        return {"message": "No services registered"}

    fleet = []
    for sid in services:
        _init_service(sid)
        dim_scores = _current_scores(sid)
        composite = _composite_score(dim_scores)
        fleet.append({"service_id": sid, "name": services[sid]["name"], "tier": services[sid]["tier"], "composite": composite, "dimensions": dim_scores})

    fleet_avg = round(sum(f["composite"] for f in fleet) / len(fleet), 1)
    dim_avgs = {}
    for dim in Dimension:
        dim_avgs[dim.value] = round(sum(f["dimensions"][dim.value] for f in fleet) / len(fleet), 1)

    above_avg = [f for f in fleet if f["composite"] >= fleet_avg]
    below_avg = [f for f in fleet if f["composite"] < fleet_avg]

    return {
        "fleet_average_composite": fleet_avg,
        "fleet_dimension_averages": dim_avgs,
        "above_average": len(above_avg),
        "below_average": len(below_avg),
        "services": sorted(fleet, key=lambda f: f["composite"], reverse=True),
    }

# ── Tier Compliance ──────────────────────────────────────────────────
@app.get("/v1/tier-compliance")
def tier_compliance():
    report = {"platinum": {"total": 0, "compliant": 0}, "gold": {"total": 0, "compliant": 0}, "silver": {"total": 0, "compliant": 0}, "bronze": {"total": 0, "compliant": 0}}
    for sid, s in services.items():
        _init_service(sid)
        tier = s["tier"]
        report[tier]["total"] += 1
        dim_scores = _current_scores(sid)
        composite = _composite_score(dim_scores)
        if composite >= TIER_THRESHOLDS[tier]:
            report[tier]["compliant"] += 1
    for tier in report:
        total = report[tier]["total"]
        report[tier]["compliance_rate"] = round(report[tier]["compliant"] / max(total, 1), 3)
    return report

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    by_tier = {}
    by_type = {}
    composites = []
    for sid, s in services.items():
        _init_service(sid)
        by_tier[s["tier"]] = by_tier.get(s["tier"], 0) + 1
        by_type[s["service_type"]] = by_type.get(s["service_type"], 0) + 1
        composites.append(_composite_score(_current_scores(sid)))

    total_measurements = sum(sum(len(s.get("scores", {}).get(d.value, [])) for d in Dimension) for s in services.values())
    return {
        "total_services": len(services),
        "by_tier": by_tier,
        "by_type": by_type,
        "avg_composite_score": round(sum(composites) / max(len(composites), 1), 1),
        "min_composite_score": min(composites, default=0),
        "max_composite_score": max(composites, default=0),
        "total_measurements": total_measurements,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9918)
