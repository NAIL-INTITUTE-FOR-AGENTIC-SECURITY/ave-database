"""Capability Discovery Agent — Phase 29 Service 3 · Port 9922"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random

app = FastAPI(title="Capability Discovery Agent", version="0.29.3")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class SystemType(str, Enum):
    llm = "llm"
    classifier = "classifier"
    detector = "detector"
    generator = "generator"
    multi_agent = "multi_agent"
    pipeline = "pipeline"

class ProbeType(str, Enum):
    boundary_test = "boundary_test"
    adversarial_input = "adversarial_input"
    capability_elicitation = "capability_elicitation"
    stress_test = "stress_test"
    cross_domain = "cross_domain"
    composition_test = "composition_test"
    edge_case = "edge_case"
    emergent_behaviour = "emergent_behaviour"

class CampaignState(str, Enum):
    planned = "planned"
    probing = "probing"
    analysing = "analysing"
    reporting = "reporting"
    archived = "archived"

CAMP_TRANSITIONS = {
    "planned": ["probing"],
    "probing": ["analysing"],
    "analysing": ["reporting"],
    "reporting": ["archived"],
}

class CapCategory(str, Enum):
    declared = "declared"
    undeclared = "undeclared"
    emergent = "emergent"
    degraded = "degraded"

class BehaviourType(str, Enum):
    expected = "expected"
    enhanced = "enhanced"
    degraded = "degraded"
    unexpected = "unexpected"
    dangerous = "dangerous"

class RiskLevel(str, Enum):
    benign = "benign"
    monitor = "monitor"
    restrict = "restrict"
    block = "block"

# ── Models ───────────────────────────────────────────────────────────
class SystemCreate(BaseModel):
    name: str
    system_type: SystemType
    version: str = "1.0.0"
    declared_capabilities: list[str] = []
    description: str = ""

class CampaignCreate(BaseModel):
    name: str
    target_system_id: str
    probe_types: list[ProbeType] = []
    description: str = ""

class ProbeExec(BaseModel):
    probe_type: ProbeType
    input_description: str = ""

# ── Stores ───────────────────────────────────────────────────────────
systems: dict[str, dict] = {}
campaigns: dict[str, dict] = {}

def _now():
    return datetime.now(timezone.utc).isoformat()

# ── Simulated Probe Results ──────────────────────────────────────────
def _sim_probe(system: dict, probe_type: str) -> dict:
    """Simulate probe execution and capability discovery."""
    cap_cats = list(CapCategory)
    beh_types = list(BehaviourType)
    risk_levels = list(RiskLevel)

    # Probability weights depend on probe type
    if probe_type in ("adversarial_input", "edge_case"):
        cap_weights = [0.1, 0.3, 0.2, 0.4]  # more degraded/undeclared
        beh_weights = [0.1, 0.05, 0.35, 0.35, 0.15]
    elif probe_type in ("emergent_behaviour", "composition_test"):
        cap_weights = [0.1, 0.25, 0.5, 0.15]  # more emergent
        beh_weights = [0.15, 0.2, 0.1, 0.4, 0.15]
    else:
        cap_weights = [0.4, 0.25, 0.15, 0.2]
        beh_weights = [0.4, 0.2, 0.15, 0.2, 0.05]

    cap = random.choices(cap_cats, weights=cap_weights, k=1)[0]
    beh = random.choices(beh_types, weights=beh_weights, k=1)[0]
    confidence = round(random.uniform(0.4, 0.95), 3)

    risk = "benign"
    if beh in ("unexpected", "dangerous"):
        risk = random.choice(["monitor", "restrict", "block"])
    elif cap == "emergent":
        risk = random.choice(["monitor", "restrict"])

    capability_name = f"{probe_type}_{random.choice(['handling', 'response', 'processing', 'generation', 'classification'])}"

    return {
        "capability_discovered": capability_name,
        "category": cap.value,
        "behaviour_type": beh.value,
        "confidence": confidence,
        "risk_level": risk,
        "details": f"Simulated {probe_type} probe on {system['name']} v{system['version']}",
    }

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "capability-discovery-agent",
        "status": "healthy",
        "version": "0.29.3",
        "systems": len(systems),
        "campaigns": len(campaigns),
    }

# ── Systems ──────────────────────────────────────────────────────────
@app.post("/v1/systems", status_code=201)
def create_system(body: SystemCreate):
    sid = str(uuid.uuid4())
    rec = {
        "id": sid,
        **body.model_dump(),
        "capability_map": [{"name": c, "category": "declared", "behaviour": "expected", "risk": "benign", "confidence": 1.0} for c in body.declared_capabilities],
        "boundaries": [],
        "previous_versions": [],
        "created_at": _now(),
    }
    systems[sid] = rec
    return rec

@app.get("/v1/systems")
def list_systems(system_type: Optional[SystemType] = None):
    out = list(systems.values())
    if system_type:
        out = [s for s in out if s["system_type"] == system_type]
    enriched = []
    for s in out:
        cats = {}
        for c in s["capability_map"]:
            cats[c["category"]] = cats.get(c["category"], 0) + 1
        enriched.append({**{k: v for k, v in s.items() if k not in ("capability_map", "boundaries", "previous_versions")}, "total_capabilities": len(s["capability_map"]), "by_category": cats})
    return enriched

@app.get("/v1/systems/{sid}")
def get_system(sid: str):
    if sid not in systems:
        raise HTTPException(404, "System not found")
    return systems[sid]

# ── Campaigns ────────────────────────────────────────────────────────
@app.post("/v1/campaigns", status_code=201)
def create_campaign(body: CampaignCreate):
    if body.target_system_id not in systems:
        raise HTTPException(404, "Target system not found")
    cid = str(uuid.uuid4())
    rec = {
        "id": cid,
        **body.model_dump(),
        "state": "planned",
        "probes_executed": [],
        "discoveries": [],
        "created_at": _now(),
    }
    campaigns[cid] = rec
    return rec

@app.get("/v1/campaigns")
def list_campaigns(state: Optional[CampaignState] = None):
    out = list(campaigns.values())
    if state:
        out = [c for c in out if c["state"] == state]
    return out

@app.get("/v1/campaigns/{cid}")
def get_campaign(cid: str):
    if cid not in campaigns:
        raise HTTPException(404, "Campaign not found")
    return campaigns[cid]

@app.patch("/v1/campaigns/{cid}/advance")
def advance_campaign(cid: str, target_state: CampaignState = Query(...)):
    if cid not in campaigns:
        raise HTTPException(404, "Campaign not found")
    c = campaigns[cid]
    allowed = CAMP_TRANSITIONS.get(c["state"], [])
    if target_state not in allowed:
        raise HTTPException(400, f"Cannot transition from {c['state']} to {target_state}")
    c["state"] = target_state
    return c

# ── Probe ────────────────────────────────────────────────────────────
@app.post("/v1/campaigns/{cid}/probe")
def execute_probe(cid: str, body: ProbeExec):
    if cid not in campaigns:
        raise HTTPException(404, "Campaign not found")
    camp = campaigns[cid]
    if camp["state"] not in ("planned", "probing"):
        raise HTTPException(400, "Campaign must be in planned or probing state")
    camp["state"] = "probing"

    system = systems.get(camp["target_system_id"])
    if not system:
        raise HTTPException(404, "Target system not found")

    result = _sim_probe(system, body.probe_type)
    probe_rec = {
        "id": str(uuid.uuid4()),
        "probe_type": body.probe_type,
        "input_description": body.input_description,
        **result,
        "executed_at": _now(),
    }
    camp["probes_executed"].append(probe_rec)

    # Add to capability map if new
    existing_names = {c["name"] for c in system["capability_map"]}
    if result["capability_discovered"] not in existing_names:
        system["capability_map"].append({
            "name": result["capability_discovered"],
            "category": result["category"],
            "behaviour": result["behaviour_type"],
            "risk": result["risk_level"],
            "confidence": result["confidence"],
            "discovered_by_campaign": cid,
            "discovered_at": _now(),
        })
        camp["discoveries"].append(result["capability_discovered"])

    return probe_rec

# ── Capability Map ───────────────────────────────────────────────────
@app.get("/v1/systems/{sid}/capabilities")
def get_capabilities(sid: str, category: Optional[CapCategory] = None):
    if sid not in systems:
        raise HTTPException(404, "System not found")
    caps = systems[sid]["capability_map"]
    if category:
        caps = [c for c in caps if c["category"] == category]
    by_cat = {}
    for c in caps:
        by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
    by_risk = {}
    for c in caps:
        by_risk[c["risk"]] = by_risk.get(c["risk"], 0) + 1
    return {"system_id": sid, "total": len(caps), "by_category": by_cat, "by_risk": by_risk, "capabilities": caps}

# ── Boundaries ───────────────────────────────────────────────────────
@app.get("/v1/systems/{sid}/boundaries")
def get_boundaries(sid: str):
    if sid not in systems:
        raise HTTPException(404, "System not found")
    s = systems[sid]
    # Generate boundaries from probes
    probes = []
    for camp in campaigns.values():
        if camp["target_system_id"] == sid:
            probes.extend(camp["probes_executed"])

    stress_probes = [p for p in probes if p["probe_type"] in ("stress_test", "boundary_test")]
    boundaries = {
        "system_id": sid,
        "total_probes_analysed": len(probes),
        "identified_boundaries": [],
    }
    if stress_probes:
        boundaries["identified_boundaries"].append({"type": "load_limit", "description": f"Estimated from {len(stress_probes)} stress/boundary probes", "confidence": round(min(0.9, len(stress_probes) * 0.15), 2)})

    degraded = [c for c in s["capability_map"] if c["category"] == "degraded"]
    if degraded:
        boundaries["identified_boundaries"].append({"type": "accuracy_threshold", "description": f"{len(degraded)} capabilities show degradation", "confidence": 0.7})

    return boundaries

# ── Diff ─────────────────────────────────────────────────────────────
@app.get("/v1/systems/{sid}/diff")
def capability_diff(sid: str):
    if sid not in systems:
        raise HTTPException(404, "System not found")
    s = systems[sid]
    current = s["capability_map"]
    previous = s.get("previous_versions", [])

    if not previous:
        return {"system_id": sid, "message": "No previous version to compare", "current_count": len(current)}

    prev_names = set(previous[-1].get("capability_names", []))
    curr_names = set(c["name"] for c in current)

    added = curr_names - prev_names
    removed = prev_names - curr_names
    unchanged = curr_names & prev_names

    return {
        "system_id": sid,
        "current_version": s["version"],
        "added": list(added),
        "removed": list(removed),
        "unchanged_count": len(unchanged),
        "total_current": len(current),
    }

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    all_caps = []
    for s in systems.values():
        all_caps.extend(s["capability_map"])

    by_cat = {}
    for c in all_caps:
        by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
    by_risk = {}
    for c in all_caps:
        by_risk[c["risk"]] = by_risk.get(c["risk"], 0) + 1
    by_behaviour = {}
    for c in all_caps:
        by_behaviour[c.get("behaviour", "unknown")] = by_behaviour.get(c.get("behaviour", "unknown"), 0) + 1

    total_probes = sum(len(c["probes_executed"]) for c in campaigns.values())
    total_discoveries = sum(len(c["discoveries"]) for c in campaigns.values())

    return {
        "total_systems": len(systems),
        "total_campaigns": len(campaigns),
        "total_capabilities_mapped": len(all_caps),
        "by_category": by_cat,
        "by_risk": by_risk,
        "by_behaviour": by_behaviour,
        "total_probes_executed": total_probes,
        "total_new_discoveries": total_discoveries,
        "emergent_count": by_cat.get("emergent", 0),
        "dangerous_count": by_behaviour.get("dangerous", 0),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9922)
