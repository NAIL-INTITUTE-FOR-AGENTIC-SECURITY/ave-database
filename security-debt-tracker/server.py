"""Security Debt Tracker — Phase 27 Service 5 · Port 9914"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, math

app = FastAPI(title="Security Debt Tracker", version="0.27.5")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class SystemType(str, Enum):
    application = "application"
    infrastructure = "infrastructure"
    data_store = "data_store"
    network = "network"
    iot = "iot"
    ai_model = "ai_model"

class Criticality(str, Enum):
    mission_critical = "mission_critical"
    business_critical = "business_critical"
    operational = "operational"
    support = "support"

CRITICALITY_FACTOR = {"mission_critical": 3.0, "business_critical": 2.0, "operational": 1.0, "support": 0.5}

class DebtType(str, Enum):
    unpatched_vuln = "unpatched_vuln"
    outdated_dependency = "outdated_dependency"
    missing_encryption = "missing_encryption"
    weak_auth = "weak_auth"
    no_mfa = "no_mfa"
    insufficient_logging = "insufficient_logging"
    missing_backup = "missing_backup"
    deprecated_protocol = "deprecated_protocol"
    hardcoded_secret = "hardcoded_secret"
    no_rate_limit = "no_rate_limit"

DEBT_INTEREST_RATE = {
    "unpatched_vuln": 0.15, "outdated_dependency": 0.08, "missing_encryption": 0.12,
    "weak_auth": 0.10, "no_mfa": 0.07, "insufficient_logging": 0.05,
    "missing_backup": 0.09, "deprecated_protocol": 0.06, "hardcoded_secret": 0.14,
    "no_rate_limit": 0.04,
}

# ── Models ───────────────────────────────────────────────────────────
class SystemCreate(BaseModel):
    name: str
    system_type: SystemType
    criticality: Criticality = Criticality.operational
    owner: str = ""
    tech_stack: list[str] = []

class DebtItemCreate(BaseModel):
    system_id: str
    debt_type: DebtType
    description: str = ""
    estimated_effort_hours: float = Field(4.0, ge=0.5)
    risk_weight: int = Field(5, ge=1, le=10)

class SprintPlanRequest(BaseModel):
    capacity_hours: float = Field(40, ge=1)

# ── Stores ───────────────────────────────────────────────────────────
systems: dict[str, dict] = {}
debt_items: dict[str, dict] = {}
resolved_log: list[dict] = []

def _now():
    return datetime.now(timezone.utc).isoformat()

def _age_days(created_at: str) -> int:
    try:
        created = datetime.fromisoformat(created_at)
        now = datetime.now(timezone.utc)
        return max(1, (now - created).days)
    except Exception:
        return 1

def _age_multiplier(age_days: int) -> float:
    """10% increase per 30 days of age."""
    return 1 + 0.1 * (age_days / 30)

def _debt_score(item: dict) -> float:
    age = _age_days(item["created_at"])
    crit = CRITICALITY_FACTOR.get(
        systems.get(item["system_id"], {}).get("criticality", "operational"), 1.0
    )
    return round(item["risk_weight"] * _age_multiplier(age) * crit, 2)

def _interest(item: dict) -> float:
    rate = DEBT_INTEREST_RATE.get(item["debt_type"], 0.05)
    age = _age_days(item["created_at"])
    return round(item["risk_weight"] * rate * (age / 30), 2)

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "security-debt-tracker",
        "status": "healthy",
        "version": "0.27.5",
        "systems": len(systems),
        "open_debt_items": sum(1 for d in debt_items.values() if d["state"] == "open"),
    }

# ── System CRUD ──────────────────────────────────────────────────────
@app.post("/v1/systems", status_code=201)
def create_system(body: SystemCreate):
    sid = str(uuid.uuid4())
    rec = {"id": sid, **body.model_dump(), "created_at": _now()}
    systems[sid] = rec
    return rec

@app.get("/v1/systems")
def list_systems(system_type: Optional[SystemType] = None, criticality: Optional[Criticality] = None):
    out = list(systems.values())
    if system_type:
        out = [s for s in out if s["system_type"] == system_type]
    if criticality:
        out = [s for s in out if s["criticality"] == criticality]
    return out

@app.get("/v1/systems/{sid}")
def get_system(sid: str):
    if sid not in systems:
        raise HTTPException(404, "System not found")
    sys_items = [d for d in debt_items.values() if d["system_id"] == sid and d["state"] == "open"]
    debt_score = sum(_debt_score(d) for d in sys_items)
    interest = sum(_interest(d) for d in sys_items)
    return {
        **systems[sid],
        "open_debt_items": len(sys_items),
        "debt_score": round(debt_score, 1),
        "accumulated_interest": round(interest, 1),
    }

# ── Debt Items ───────────────────────────────────────────────────────
@app.post("/v1/debt-items", status_code=201)
def create_debt_item(body: DebtItemCreate):
    if body.system_id not in systems:
        raise HTTPException(404, "System not found")
    did = str(uuid.uuid4())
    rec = {
        "id": did,
        **body.model_dump(),
        "state": "open",
        "created_at": _now(),
        "resolved_at": None,
    }
    debt_items[did] = rec
    return rec

@app.get("/v1/debt-items")
def list_debt_items(
    debt_type: Optional[DebtType] = None,
    system_id: Optional[str] = None,
    state: Optional[str] = Query(None, pattern="^(open|resolved)$"),
):
    out = list(debt_items.values())
    if debt_type:
        out = [d for d in out if d["debt_type"] == debt_type]
    if system_id:
        out = [d for d in out if d["system_id"] == system_id]
    if state:
        out = [d for d in out if d["state"] == state]
    # Enrich with scores
    for d in out:
        d["debt_score"] = _debt_score(d)
        d["interest"] = _interest(d)
    return sorted(out, key=lambda d: d["debt_score"], reverse=True)

@app.patch("/v1/debt-items/{did}/resolve")
def resolve_debt_item(did: str):
    if did not in debt_items:
        raise HTTPException(404, "Debt item not found")
    d = debt_items[did]
    if d["state"] == "resolved":
        raise HTTPException(400, "Already resolved")
    d["state"] = "resolved"
    d["resolved_at"] = _now()
    resolved_log.append({"debt_item_id": did, "system_id": d["system_id"], "debt_type": d["debt_type"], "effort_hours": d["estimated_effort_hours"], "resolved_at": _now()})
    return d

# ── Velocity ─────────────────────────────────────────────────────────
@app.get("/v1/velocity")
def debt_velocity():
    open_items = [d for d in debt_items.values() if d["state"] == "open"]
    resolved = [d for d in debt_items.values() if d["state"] == "resolved"]
    total_open = len(open_items)
    total_resolved = len(resolved)
    # Simplified weekly rate estimates
    new_per_week = round(total_open / max(4, 1), 1)  # assume ~4 weeks of data
    resolved_per_week = round(total_resolved / max(4, 1), 1)
    net = round(new_per_week - resolved_per_week, 1)
    weeks_to_zero = round(total_open / max(resolved_per_week, 0.1), 1) if net <= 0 else float("inf")
    return {
        "open_items": total_open,
        "resolved_items": total_resolved,
        "new_per_week": new_per_week,
        "resolved_per_week": resolved_per_week,
        "net_velocity": net,
        "velocity_trend": "growing" if net > 0 else "shrinking" if net < 0 else "stable",
        "weeks_to_zero": weeks_to_zero if weeks_to_zero != float("inf") else "never_at_current_rate",
    }

# ── Prioritised Backlog ─────────────────────────────────────────────
@app.get("/v1/prioritised")
def prioritised_backlog(quick_wins_only: bool = False):
    open_items = [d for d in debt_items.values() if d["state"] == "open"]
    for d in open_items:
        d["debt_score"] = _debt_score(d)
        d["roi"] = round(d["debt_score"] / max(d["estimated_effort_hours"], 0.5), 2)
    if quick_wins_only:
        open_items = [d for d in open_items if d["estimated_effort_hours"] <= 4 and d["risk_weight"] >= 5]
    return sorted(open_items, key=lambda d: d["roi"], reverse=True)

# ── Sprint Plan ──────────────────────────────────────────────────────
@app.post("/v1/sprint-plan")
def generate_sprint_plan(body: SprintPlanRequest):
    backlog = prioritised_backlog()
    selected = []
    remaining_hours = body.capacity_hours
    total_score_reduction = 0
    for item in backlog:
        if item["estimated_effort_hours"] <= remaining_hours:
            selected.append({
                "debt_item_id": item["id"],
                "system_id": item["system_id"],
                "debt_type": item["debt_type"],
                "effort_hours": item["estimated_effort_hours"],
                "debt_score": item["debt_score"],
            })
            remaining_hours -= item["estimated_effort_hours"]
            total_score_reduction += item["debt_score"]
    return {
        "capacity_hours": body.capacity_hours,
        "hours_allocated": round(body.capacity_hours - remaining_hours, 1),
        "hours_remaining": round(remaining_hours, 1),
        "items_selected": len(selected),
        "expected_debt_score_reduction": round(total_score_reduction, 1),
        "items": selected,
    }

# ── Forecast ─────────────────────────────────────────────────────────
@app.get("/v1/forecast")
def debt_forecast():
    open_items = [d for d in debt_items.values() if d["state"] == "open"]
    current_score = sum(_debt_score(d) for d in open_items)
    current_interest = sum(_interest(d) for d in open_items)

    forecasts = {}
    for days in (30, 60, 90):
        # Score grows with age
        projected_score = sum(
            d["risk_weight"] * _age_multiplier(_age_days(d["created_at"]) + days) * CRITICALITY_FACTOR.get(systems.get(d["system_id"], {}).get("criticality", "operational"), 1.0)
            for d in open_items
        )
        projected_interest = sum(
            d["risk_weight"] * DEBT_INTEREST_RATE.get(d["debt_type"], 0.05) * ((_age_days(d["created_at"]) + days) / 30)
            for d in open_items
        )
        forecasts[f"{days}d"] = {
            "projected_debt_score": round(projected_score, 1),
            "projected_interest": round(projected_interest, 1),
            "score_growth_pct": round((projected_score - current_score) / max(current_score, 1) * 100, 1),
        }
    return {
        "current_debt_score": round(current_score, 1),
        "current_interest": round(current_interest, 1),
        "open_items": len(open_items),
        "forecasts": forecasts,
    }

# ── Executive Dashboard ──────────────────────────────────────────────
@app.get("/v1/executive-dashboard")
def executive_dashboard():
    open_items = [d for d in debt_items.values() if d["state"] == "open"]
    total_score = sum(_debt_score(d) for d in open_items)
    total_interest = sum(_interest(d) for d in open_items)

    # Top 5 riskiest systems
    sys_scores = {}
    for d in open_items:
        sys_scores[d["system_id"]] = sys_scores.get(d["system_id"], 0) + _debt_score(d)
    top_5 = sorted(sys_scores.items(), key=lambda x: x[1], reverse=True)[:5]
    top_systems = [{"system_id": sid, "name": systems.get(sid, {}).get("name", "unknown"), "debt_score": round(score, 1)} for sid, score in top_5]

    # Age distribution
    age_buckets = {"<7d": 0, "7-30d": 0, "30-90d": 0, ">90d": 0}
    for d in open_items:
        age = _age_days(d["created_at"])
        if age < 7:
            age_buckets["<7d"] += 1
        elif age < 30:
            age_buckets["7-30d"] += 1
        elif age < 90:
            age_buckets["30-90d"] += 1
        else:
            age_buckets[">90d"] += 1

    return {
        "total_debt_score": round(total_score, 1),
        "total_interest": round(total_interest, 1),
        "open_items": len(open_items),
        "resolved_items": len(resolved_log),
        "top_5_riskiest_systems": top_systems,
        "debt_age_distribution": age_buckets,
        "by_type": {dt: sum(1 for d in open_items if d["debt_type"] == dt) for dt in set(d["debt_type"] for d in open_items)} if open_items else {},
    }

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    dl = list(debt_items.values())
    by_type = {}
    for d in dl:
        by_type[d["debt_type"]] = by_type.get(d["debt_type"], 0) + 1
    by_state = {}
    for d in dl:
        by_state[d["state"]] = by_state.get(d["state"], 0) + 1
    by_system = {}
    for d in dl:
        by_system[d["system_id"]] = by_system.get(d["system_id"], 0) + 1
    total_effort = sum(d["estimated_effort_hours"] for d in dl if d["state"] == "open")
    return {
        "total_systems": len(systems),
        "total_debt_items": len(dl),
        "by_type": by_type,
        "by_state": by_state,
        "by_system": by_system,
        "total_open_effort_hours": round(total_effort, 1),
        "total_resolved": len(resolved_log),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9914)
