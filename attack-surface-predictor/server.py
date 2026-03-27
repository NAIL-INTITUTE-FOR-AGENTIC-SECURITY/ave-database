"""Attack Surface Predictor — Phase 27 Service 1 · Port 9910"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random, math

app = FastAPI(title="Attack Surface Predictor", version="0.27.1")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class AssetType(str, Enum):
    service = "service"
    api = "api"
    database = "database"
    storage = "storage"
    network = "network"
    compute = "compute"
    model = "model"

class ExposureLevel(str, Enum):
    public = "public"
    internal = "internal"
    restricted = "restricted"
    isolated = "isolated"

EXPOSURE_WEIGHT = {"public": 1.0, "internal": 0.6, "restricted": 0.3, "isolated": 0.1}

class ChangeMagnitude(str, Enum):
    minor = "minor"
    moderate = "moderate"
    major = "major"
    critical = "critical"

MAGNITUDE_FACTOR = {"minor": 0.05, "moderate": 0.15, "major": 0.35, "critical": 0.60}

class ChangeType(str, Enum):
    deploy = "deploy"
    config_change = "config_change"
    dependency_update = "dependency_update"
    infra_scale = "infra_scale"
    feature_toggle = "feature_toggle"
    access_grant = "access_grant"
    decommission = "decommission"

CHANGE_DIRECTION = {
    "deploy": 1, "config_change": 0.5, "dependency_update": 0.3,
    "infra_scale": 0.8, "feature_toggle": 0.2, "access_grant": 0.6,
    "decommission": -1,
}

# ── Models ───────────────────────────────────────────────────────────
class AssetCreate(BaseModel):
    name: str
    asset_type: AssetType
    exposure_level: ExposureLevel = ExposureLevel.internal
    technology_stack: list[str] = []
    dependencies: list[str] = []
    entry_points: int = Field(1, ge=0)
    data_sensitivity: float = Field(0.5, ge=0, le=1)

class ChangeCreate(BaseModel):
    description: str
    change_type: ChangeType
    magnitude: ChangeMagnitude = ChangeMagnitude.moderate
    affected_asset_ids: list[str] = []

# ── Stores ───────────────────────────────────────────────────────────
assets: dict[str, dict] = {}
changes: dict[str, dict] = {}
predictions: list[dict] = []

def _now():
    return datetime.now(timezone.utc).isoformat()

def _surface_score(asset: dict) -> float:
    exposure = EXPOSURE_WEIGHT.get(asset["exposure_level"], 0.5)
    complexity = min(1.0, len(asset["technology_stack"]) * 0.15 + len(asset["dependencies"]) * 0.1)
    connectivity = min(1.0, asset["entry_points"] * 0.1)
    return round((exposure * 300 + complexity * 350 + connectivity * 350) * (1 + asset["data_sensitivity"]), 1)

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "attack-surface-predictor",
        "status": "healthy",
        "version": "0.27.1",
        "assets": len(assets),
        "changes": len(changes),
    }

# ── Asset CRUD ───────────────────────────────────────────────────────
@app.post("/v1/assets", status_code=201)
def create_asset(body: AssetCreate):
    aid = str(uuid.uuid4())
    rec = {
        "id": aid,
        **body.model_dump(),
        "surface_score": 0.0,
        "risk_score": 0.0,
        "created_at": _now(),
    }
    rec["surface_score"] = _surface_score(rec)
    rec["risk_score"] = round(rec["surface_score"] / 10, 1)
    assets[aid] = rec
    return rec

@app.get("/v1/assets")
def list_assets(asset_type: Optional[AssetType] = None, exposure: Optional[ExposureLevel] = None):
    out = list(assets.values())
    if asset_type:
        out = [a for a in out if a["asset_type"] == asset_type]
    if exposure:
        out = [a for a in out if a["exposure_level"] == exposure]
    return sorted(out, key=lambda x: x["risk_score"], reverse=True)

@app.get("/v1/assets/{aid}")
def get_asset(aid: str):
    if aid not in assets:
        raise HTTPException(404, "Asset not found")
    a = assets[aid]
    a["surface_score"] = _surface_score(a)
    return a

# ── Change Ingestion ─────────────────────────────────────────────────
@app.post("/v1/changes", status_code=201)
def create_change(body: ChangeCreate):
    for aid in body.affected_asset_ids:
        if aid not in assets:
            raise HTTPException(404, f"Asset {aid} not found")
    cid = str(uuid.uuid4())
    rec = {"id": cid, **body.model_dump(), "created_at": _now(), "prediction": None}
    changes[cid] = rec
    return rec

@app.get("/v1/changes")
def list_changes(change_type: Optional[ChangeType] = None):
    out = list(changes.values())
    if change_type:
        out = [c for c in out if c["change_type"] == change_type]
    return out

# ── Impact Prediction ────────────────────────────────────────────────
@app.post("/v1/changes/{cid}/predict")
def predict_impact(cid: str):
    if cid not in changes:
        raise HTTPException(404, "Change not found")
    ch = changes[cid]
    direction = CHANGE_DIRECTION.get(ch["change_type"], 0.5)
    mag = MAGNITUDE_FACTOR.get(ch["magnitude"], 0.15)

    affected = [assets[aid] for aid in ch["affected_asset_ids"] if aid in assets]
    before_total = sum(_surface_score(a) for a in affected)

    for a in affected:
        delta = a["surface_score"] * mag * direction
        a["entry_points"] = max(0, a["entry_points"] + int(direction * 2))
        a["surface_score"] = max(0, round(a["surface_score"] + delta, 1))
        a["risk_score"] = round(a["surface_score"] / 10, 1)

    after_total = sum(_surface_score(a) for a in affected)
    delta_pct = round((after_total - before_total) / max(before_total, 1) * 100, 1)

    pred = {
        "change_id": cid,
        "surface_before": round(before_total, 1),
        "surface_after": round(after_total, 1),
        "delta_percentage": delta_pct,
        "direction": "expanding" if delta_pct > 0 else "contracting" if delta_pct < 0 else "stable",
        "affected_assets": len(affected),
        "risk_score_delta": round((after_total - before_total) / 10, 1),
        "predicted_at": _now(),
    }
    ch["prediction"] = pred
    predictions.append(pred)
    return pred

# ── Surface Overview ─────────────────────────────────────────────────
@app.get("/v1/surface")
def surface_overview():
    al = list(assets.values())
    total = sum(a["surface_score"] for a in al)
    by_type = {}
    for a in al:
        by_type[a["asset_type"]] = by_type.get(a["asset_type"], 0) + a["surface_score"]
    by_exposure = {}
    for a in al:
        by_exposure[a["exposure_level"]] = by_exposure.get(a["exposure_level"], 0) + a["surface_score"]
    return {
        "total_surface_area": round(total, 1),
        "asset_count": len(al),
        "by_type": {k: round(v, 1) for k, v in by_type.items()},
        "by_exposure": {k: round(v, 1) for k, v in by_exposure.items()},
        "avg_risk_score": round(sum(a["risk_score"] for a in al) / max(len(al), 1), 1),
    }

# ── Forecast ─────────────────────────────────────────────────────────
@app.get("/v1/surface/forecast")
def surface_forecast():
    current = sum(a["surface_score"] for a in assets.values())
    recent_deltas = [p["delta_percentage"] for p in predictions[-20:]] if predictions else [0]
    avg_delta = sum(recent_deltas) / max(len(recent_deltas), 1)
    weekly_growth = avg_delta / 100

    forecasts = {}
    for days in (7, 30, 90):
        weeks = days / 7
        projected = current * (1 + weekly_growth) ** weeks
        forecasts[f"{days}d"] = {
            "projected_surface": round(projected, 1),
            "growth_percentage": round((projected - current) / max(current, 1) * 100, 1),
            "breach_probability": round(min(1.0, projected / 10000), 3),
        }
    return {"current_surface": round(current, 1), "avg_weekly_growth_pct": round(weekly_growth * 100, 2), "forecasts": forecasts}

# ── Hotspots ─────────────────────────────────────────────────────────
@app.get("/v1/hotspots")
def hotspots(limit: int = Query(10, ge=1)):
    sorted_assets = sorted(assets.values(), key=lambda a: a["risk_score"], reverse=True)
    return [{"asset_id": a["id"], "name": a["name"], "risk_score": a["risk_score"], "surface_score": a["surface_score"], "exposure": a["exposure_level"]} for a in sorted_assets[:limit]]

# ── Recommendations ──────────────────────────────────────────────────
@app.get("/v1/recommendations")
def recommendations():
    recs = []
    for a in assets.values():
        if a["exposure_level"] == "public" and a["risk_score"] > 50:
            recs.append({"asset_id": a["id"], "name": a["name"], "action": "reduce_exposure", "detail": "Move from public to internal if possible", "effort_hours": 8, "risk_reduction": 30})
        if a["entry_points"] > 10:
            recs.append({"asset_id": a["id"], "name": a["name"], "action": "harden_entry_point", "detail": f"Reduce {a['entry_points']} entry points", "effort_hours": 4, "risk_reduction": 15})
        if len(a["dependencies"]) > 5:
            recs.append({"asset_id": a["id"], "name": a["name"], "action": "reduce_dependencies", "detail": f"Audit {len(a['dependencies'])} dependencies", "effort_hours": 12, "risk_reduction": 10})
    return sorted(recs, key=lambda r: r["risk_reduction"] / max(r["effort_hours"], 1), reverse=True)

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    al = list(assets.values())
    by_type = {}
    for a in al:
        by_type[a["asset_type"]] = by_type.get(a["asset_type"], 0) + 1
    by_exposure = {}
    for a in al:
        by_exposure[a["exposure_level"]] = by_exposure.get(a["exposure_level"], 0) + 1
    return {
        "total_assets": len(al),
        "assets_by_type": by_type,
        "assets_by_exposure": by_exposure,
        "total_changes": len(changes),
        "total_predictions": len(predictions),
        "avg_surface_score": round(sum(a["surface_score"] for a in al) / max(len(al), 1), 1),
        "avg_risk_score": round(sum(a["risk_score"] for a in al) / max(len(al), 1), 1),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9910)
