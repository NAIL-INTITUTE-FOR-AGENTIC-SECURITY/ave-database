"""Threat Evolution Modeller — Phase 27 Service 2 · Port 9911"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random

app = FastAPI(title="Threat Evolution Modeller", version="0.27.2")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class ActorType(str, Enum):
    nation_state = "nation_state"
    organised_crime = "organised_crime"
    hacktivist = "hacktivist"
    insider = "insider"
    script_kiddie = "script_kiddie"
    apt_group = "apt_group"

class CapabilityType(str, Enum):
    tooling = "tooling"
    infrastructure = "infrastructure"
    tradecraft = "tradecraft"
    social_engineering = "social_engineering"
    zero_day = "zero_day"
    supply_chain = "supply_chain"

class MaturityLevel(str, Enum):
    experimental = "experimental"
    developing = "developing"
    operational = "operational"
    advanced = "advanced"

MATURITY_SCORE = {"experimental": 1, "developing": 2, "operational": 3, "advanced": 4}

class CampaignStatus(str, Enum):
    active = "active"
    dormant = "dormant"
    concluded = "concluded"

# ── Models ───────────────────────────────────────────────────────────
class ActorCreate(BaseModel):
    name: str
    actor_type: ActorType
    sophistication_level: int = Field(5, ge=1, le=10)
    known_ttps: list[str] = []
    target_sectors: list[str] = []
    aliases: list[str] = []

class TTPObservation(BaseModel):
    tactic: str
    technique: str
    procedure: str = ""
    effectiveness_rating: float = Field(0.5, ge=0, le=1)

class CapabilityLog(BaseModel):
    capability_type: CapabilityType
    maturity_level: MaturityLevel
    description: str = ""

class CampaignCreate(BaseModel):
    name: str
    actor_id: str
    ttps_used: list[str] = []
    targets: list[str] = []
    status: CampaignStatus = CampaignStatus.active

# ── Stores ───────────────────────────────────────────────────────────
actors: dict[str, dict] = {}
campaigns: dict[str, dict] = {}
vector_predictions: list[dict] = []

def _now():
    return datetime.now(timezone.utc).isoformat()

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "threat-evolution-modeller",
        "status": "healthy",
        "version": "0.27.2",
        "actors": len(actors),
        "campaigns": len(campaigns),
        "predictions": len(vector_predictions),
    }

# ── Actor CRUD ───────────────────────────────────────────────────────
@app.post("/v1/actors", status_code=201)
def create_actor(body: ActorCreate):
    aid = str(uuid.uuid4())
    rec = {
        "id": aid,
        **body.model_dump(),
        "ttp_observations": [],
        "capability_timeline": [],
        "created_at": _now(),
    }
    actors[aid] = rec
    return rec

@app.get("/v1/actors")
def list_actors(actor_type: Optional[ActorType] = None, min_sophistication: Optional[int] = None):
    out = list(actors.values())
    if actor_type:
        out = [a for a in out if a["actor_type"] == actor_type]
    if min_sophistication is not None:
        out = [a for a in out if a["sophistication_level"] >= min_sophistication]
    return out

@app.get("/v1/actors/{aid}")
def get_actor(aid: str):
    if aid not in actors:
        raise HTTPException(404, "Actor not found")
    return actors[aid]

# ── TTP Tracking ─────────────────────────────────────────────────────
@app.post("/v1/actors/{aid}/ttps")
def record_ttp(aid: str, body: TTPObservation):
    if aid not in actors:
        raise HTTPException(404, "Actor not found")
    obs = {
        "id": str(uuid.uuid4()),
        **body.model_dump(),
        "observed_at": _now(),
    }
    actors[aid]["ttp_observations"].append(obs)
    # Auto-add to known_ttps
    ttp_key = f"{body.tactic}:{body.technique}"
    if ttp_key not in actors[aid]["known_ttps"]:
        actors[aid]["known_ttps"].append(ttp_key)
    return obs

# ── Capability Timeline ──────────────────────────────────────────────
@app.post("/v1/actors/{aid}/capabilities")
def log_capability(aid: str, body: CapabilityLog):
    if aid not in actors:
        raise HTTPException(404, "Actor not found")
    entry = {"id": str(uuid.uuid4()), **body.model_dump(), "observed_at": _now()}
    actors[aid]["capability_timeline"].append(entry)
    return entry

# ── Evolution Trajectory ─────────────────────────────────────────────
@app.get("/v1/actors/{aid}/evolution")
def get_evolution(aid: str):
    if aid not in actors:
        raise HTTPException(404, "Actor not found")
    a = actors[aid]
    caps = a["capability_timeline"]
    ttps = a["ttp_observations"]

    # Capability velocity
    cap_count = len(caps)
    ttp_count = len(ttps)

    # Sophistication trend
    if cap_count >= 2:
        recent_maturity = [MATURITY_SCORE.get(c["maturity_level"], 1) for c in caps[-5:]]
        older_maturity = [MATURITY_SCORE.get(c["maturity_level"], 1) for c in caps[:max(1, cap_count - 5)]]
        trend = "rising" if sum(recent_maturity) / len(recent_maturity) > sum(older_maturity) / len(older_maturity) else "declining" if sum(recent_maturity) / len(recent_maturity) < sum(older_maturity) / len(older_maturity) else "stable"
    else:
        trend = "insufficient_data"

    # TTP diversity
    unique_tactics = set(t["tactic"] for t in ttps)
    unique_techniques = set(t["technique"] for t in ttps)

    return {
        "actor_id": aid,
        "actor_name": a["name"],
        "sophistication_level": a["sophistication_level"],
        "sophistication_trend": trend,
        "capability_velocity": cap_count,
        "total_ttp_observations": ttp_count,
        "unique_tactics": len(unique_tactics),
        "unique_techniques": len(unique_techniques),
        "capability_types": list(set(c["capability_type"] for c in caps)),
        "highest_maturity": max((MATURITY_SCORE.get(c["maturity_level"], 1) for c in caps), default=0),
    }

# ── Predict Next Capabilities ────────────────────────────────────────
@app.post("/v1/actors/{aid}/predict")
def predict_capabilities(aid: str):
    if aid not in actors:
        raise HTTPException(404, "Actor not found")
    a = actors[aid]
    caps = a["capability_timeline"]
    existing_types = set(c["capability_type"] for c in caps)
    all_types = set(ct.value for ct in CapabilityType)
    missing = all_types - existing_types

    preds = []
    for ct in missing:
        prob = round(random.uniform(0.1, 0.8), 3)
        preds.append({
            "predicted_capability": ct,
            "probability": prob,
            "estimated_time_to_develop": f"{random.randint(1, 12)} months",
            "confidence": round(min(0.9, prob + 0.1), 3),
            "rationale": f"Based on actor sophistication ({a['sophistication_level']}/10) and existing {len(caps)} capabilities",
        })

    # Predict TTP evolution
    ttp_preds = []
    if a["ttp_observations"]:
        avg_eff = sum(t["effectiveness_rating"] for t in a["ttp_observations"]) / len(a["ttp_observations"])
        if avg_eff > 0.7:
            ttp_preds.append({"prediction": "Actor likely to refine existing high-effectiveness TTPs", "confidence": 0.8})
        else:
            ttp_preds.append({"prediction": "Actor likely to explore new TTPs due to low effectiveness", "confidence": 0.7})

    result = {
        "actor_id": aid,
        "capability_predictions": sorted(preds, key=lambda p: p["probability"], reverse=True),
        "ttp_evolution_predictions": ttp_preds,
        "predicted_at": _now(),
    }
    vector_predictions.append(result)
    return result

# ── Campaigns ────────────────────────────────────────────────────────
@app.post("/v1/campaigns", status_code=201)
def create_campaign(body: CampaignCreate):
    if body.actor_id not in actors:
        raise HTTPException(404, "Actor not found")
    cid = str(uuid.uuid4())
    rec = {"id": cid, **body.model_dump(), "created_at": _now()}
    campaigns[cid] = rec
    return rec

@app.get("/v1/campaigns")
def list_campaigns(status: Optional[CampaignStatus] = None, actor_id: Optional[str] = None):
    out = list(campaigns.values())
    if status:
        out = [c for c in out if c["status"] == status]
    if actor_id:
        out = [c for c in out if c["actor_id"] == actor_id]
    return out

# ── Threat Landscape ─────────────────────────────────────────────────
@app.get("/v1/landscape")
def threat_landscape():
    al = list(actors.values())
    by_type = {}
    for a in al:
        by_type[a["actor_type"]] = by_type.get(a["actor_type"], 0) + 1

    all_ttps = []
    for a in al:
        all_ttps.extend(a["ttp_observations"])
    tactic_freq = {}
    for t in all_ttps:
        tactic_freq[t["tactic"]] = tactic_freq.get(t["tactic"], 0) + 1

    active_campaigns = sum(1 for c in campaigns.values() if c["status"] == "active")
    avg_soph = sum(a["sophistication_level"] for a in al) / max(len(al), 1)

    return {
        "total_actors": len(al),
        "actors_by_type": by_type,
        "avg_sophistication": round(avg_soph, 1),
        "total_ttp_observations": len(all_ttps),
        "dominant_tactics": dict(sorted(tactic_freq.items(), key=lambda x: x[1], reverse=True)[:5]),
        "active_campaigns": active_campaigns,
        "total_predictions": len(vector_predictions),
    }

# ── Predictions ──────────────────────────────────────────────────────
@app.get("/v1/predictions")
def get_predictions(limit: int = Query(20, ge=1)):
    return vector_predictions[-limit:]

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    al = list(actors.values())
    cl = list(campaigns.values())
    by_actor_type = {}
    for a in al:
        by_actor_type[a["actor_type"]] = by_actor_type.get(a["actor_type"], 0) + 1
    by_campaign_status = {}
    for c in cl:
        by_campaign_status[c["status"]] = by_campaign_status.get(c["status"], 0) + 1
    total_ttps = sum(len(a["ttp_observations"]) for a in al)
    total_caps = sum(len(a["capability_timeline"]) for a in al)
    return {
        "total_actors": len(al),
        "actors_by_type": by_actor_type,
        "total_campaigns": len(cl),
        "campaigns_by_status": by_campaign_status,
        "total_ttp_observations": total_ttps,
        "total_capabilities_logged": total_caps,
        "total_predictions": len(vector_predictions),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9911)
