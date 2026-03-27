"""Incident Learning Engine — Phase 28 Service 5 · Port 9919"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid

app = FastAPI(title="Incident Learning Engine", version="0.28.5")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class IncidentType(str, Enum):
    outage = "outage"
    data_breach = "data_breach"
    performance_degradation = "performance_degradation"
    security_compromise = "security_compromise"
    data_loss = "data_loss"
    cascading_failure = "cascading_failure"

class Severity(str, Enum):
    critical = "critical"
    major = "major"
    minor = "minor"
    cosmetic = "cosmetic"

class RootCauseCategory(str, Enum):
    code_defect = "code_defect"
    config_error = "config_error"
    capacity_limit = "capacity_limit"
    dependency_failure = "dependency_failure"
    human_error = "human_error"
    security_exploit = "security_exploit"
    data_corruption = "data_corruption"
    infrastructure_fault = "infrastructure_fault"

class LessonCategory(str, Enum):
    process = "process"
    technical = "technical"
    cultural = "cultural"
    communication = "communication"

class ActionState(str, Enum):
    identified = "identified"
    assigned = "assigned"
    in_progress = "in_progress"
    completed = "completed"
    verified = "verified"

ACTION_TRANSITIONS = {
    "identified": ["assigned"],
    "assigned": ["in_progress"],
    "in_progress": ["completed"],
    "completed": ["verified"],
}

# ── Models ───────────────────────────────────────────────────────────
class IncidentCreate(BaseModel):
    title: str
    incident_type: IncidentType
    severity: Severity
    affected_systems: list[str] = []
    impact_description: str = ""
    detected_by: str = ""

class TimelineEvent(BaseModel):
    event_type: str = Field("detection", pattern="^(detection|triage|containment|mitigation|resolution|post_mortem)$")
    description: str
    actor: str = ""

class RootCauseRecord(BaseModel):
    category: RootCauseCategory
    description: str
    contributing_factors: list[str] = []

class LessonRecord(BaseModel):
    category: LessonCategory
    title: str
    description: str = ""
    recommendation: str = ""

class ActionCreate(BaseModel):
    title: str
    description: str = ""
    owner: str = ""
    due_date: str = ""
    priority: int = Field(5, ge=1, le=10)

# ── Stores ───────────────────────────────────────────────────────────
incidents: dict[str, dict] = {}
actions: dict[str, dict] = {}

def _now():
    return datetime.now(timezone.utc).isoformat()

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "incident-learning-engine",
        "status": "healthy",
        "version": "0.28.5",
        "incidents": len(incidents),
        "actions": len(actions),
    }

# ── Incidents ────────────────────────────────────────────────────────
@app.post("/v1/incidents", status_code=201)
def create_incident(body: IncidentCreate):
    iid = str(uuid.uuid4())
    rec = {
        "id": iid,
        **body.model_dump(),
        "timeline": [],
        "root_causes": [],
        "lessons": [],
        "action_ids": [],
        "status": "open",
        "created_at": _now(),
        "resolved_at": None,
    }
    incidents[iid] = rec
    return rec

@app.get("/v1/incidents")
def list_incidents(
    incident_type: Optional[IncidentType] = None,
    severity: Optional[Severity] = None,
    status: Optional[str] = Query(None, pattern="^(open|resolved)$"),
):
    out = list(incidents.values())
    if incident_type:
        out = [i for i in out if i["incident_type"] == incident_type]
    if severity:
        out = [i for i in out if i["severity"] == severity]
    if status:
        out = [i for i in out if i["status"] == status]
    return out

@app.get("/v1/incidents/{iid}")
def get_incident(iid: str):
    if iid not in incidents:
        raise HTTPException(404, "Incident not found")
    return incidents[iid]

# ── Timeline ─────────────────────────────────────────────────────────
@app.post("/v1/incidents/{iid}/timeline")
def add_timeline_event(iid: str, body: TimelineEvent):
    if iid not in incidents:
        raise HTTPException(404, "Incident not found")
    event = {"id": str(uuid.uuid4()), **body.model_dump(), "timestamp": _now()}
    incidents[iid]["timeline"].append(event)
    if body.event_type == "resolution":
        incidents[iid]["status"] = "resolved"
        incidents[iid]["resolved_at"] = _now()
    return event

# ── Root Causes ──────────────────────────────────────────────────────
@app.post("/v1/incidents/{iid}/root-causes")
def add_root_cause(iid: str, body: RootCauseRecord):
    if iid not in incidents:
        raise HTTPException(404, "Incident not found")
    rc = {"id": str(uuid.uuid4()), **body.model_dump(), "recorded_at": _now()}
    incidents[iid]["root_causes"].append(rc)
    return rc

# ── Lessons ──────────────────────────────────────────────────────────
@app.post("/v1/incidents/{iid}/lessons")
def add_lesson(iid: str, body: LessonRecord):
    if iid not in incidents:
        raise HTTPException(404, "Incident not found")
    lesson = {"id": str(uuid.uuid4()), **body.model_dump(), "recorded_at": _now()}
    incidents[iid]["lessons"].append(lesson)
    return lesson

# ── Actions ──────────────────────────────────────────────────────────
@app.post("/v1/incidents/{iid}/actions", status_code=201)
def create_action(iid: str, body: ActionCreate):
    if iid not in incidents:
        raise HTTPException(404, "Incident not found")
    aid = str(uuid.uuid4())
    rec = {
        "id": aid,
        "incident_id": iid,
        **body.model_dump(),
        "state": "identified",
        "created_at": _now(),
        "completed_at": None,
    }
    actions[aid] = rec
    incidents[iid]["action_ids"].append(aid)
    return rec

@app.patch("/v1/actions/{aid}/advance")
def advance_action(aid: str, target_state: ActionState = Query(...)):
    if aid not in actions:
        raise HTTPException(404, "Action not found")
    a = actions[aid]
    allowed = ACTION_TRANSITIONS.get(a["state"], [])
    if target_state not in allowed:
        raise HTTPException(400, f"Cannot transition from {a['state']} to {target_state}")
    a["state"] = target_state
    if target_state in ("completed", "verified"):
        a["completed_at"] = _now()
    return a

# ── Post-Mortem ──────────────────────────────────────────────────────
@app.get("/v1/incidents/{iid}/post-mortem")
def generate_post_mortem(iid: str):
    if iid not in incidents:
        raise HTTPException(404, "Incident not found")
    inc = incidents[iid]

    # Duration
    duration = "ongoing"
    if inc["resolved_at"]:
        try:
            start = datetime.fromisoformat(inc["created_at"])
            end = datetime.fromisoformat(inc["resolved_at"])
            minutes = (end - start).total_seconds() / 60
            duration = f"{round(minutes, 1)} minutes"
        except Exception:
            duration = "unknown"

    related_actions = [actions[aid] for aid in inc["action_ids"] if aid in actions]
    completed_actions = sum(1 for a in related_actions if a["state"] in ("completed", "verified"))

    return {
        "incident_id": iid,
        "title": inc["title"],
        "severity": inc["severity"],
        "type": inc["incident_type"],
        "status": inc["status"],
        "duration": duration,
        "affected_systems": inc["affected_systems"],
        "impact": inc["impact_description"],
        "timeline": inc["timeline"],
        "root_causes": inc["root_causes"],
        "contributing_factors": list(set(f for rc in inc["root_causes"] for f in rc["contributing_factors"])),
        "lessons_learned": inc["lessons"],
        "action_items": related_actions,
        "action_completion_rate": round(completed_actions / max(len(related_actions), 1), 3),
        "generated_at": _now(),
        "note": "This is a blameless post-mortem focused on systemic improvement, not individual blame.",
    }

# ── Similarity ───────────────────────────────────────────────────────
@app.get("/v1/incidents/{iid}/similar")
def find_similar(iid: str, limit: int = Query(5, ge=1)):
    if iid not in incidents:
        raise HTTPException(404, "Incident not found")
    target = incidents[iid]
    target_rc_cats = set(rc["category"] for rc in target["root_causes"])
    target_systems = set(target["affected_systems"])

    scored = []
    for oid, other in incidents.items():
        if oid == iid:
            continue
        score = 0
        # Type match
        if other["incident_type"] == target["incident_type"]:
            score += 30
        # Severity match
        if other["severity"] == target["severity"]:
            score += 10
        # Root cause overlap
        other_rc_cats = set(rc["category"] for rc in other["root_causes"])
        rc_overlap = len(target_rc_cats & other_rc_cats)
        score += rc_overlap * 20
        # System overlap
        other_systems = set(other["affected_systems"])
        sys_overlap = len(target_systems & other_systems)
        score += sys_overlap * 15

        if score > 0:
            scored.append({"incident_id": oid, "title": other["title"], "similarity_score": score, "type_match": other["incident_type"] == target["incident_type"], "root_cause_overlap": rc_overlap, "system_overlap": sys_overlap})

    return sorted(scored, key=lambda s: s["similarity_score"], reverse=True)[:limit]

# ── Patterns ─────────────────────────────────────────────────────────
@app.get("/v1/patterns")
def detect_patterns():
    all_incidents = list(incidents.values())
    if not all_incidents:
        return {"patterns": [], "message": "No incidents to analyse"}

    # Root cause frequency
    rc_freq: dict[str, int] = {}
    for inc in all_incidents:
        for rc in inc["root_causes"]:
            rc_freq[rc["category"]] = rc_freq.get(rc["category"], 0) + 1

    # Affected system frequency
    sys_freq: dict[str, int] = {}
    for inc in all_incidents:
        for s in inc["affected_systems"]:
            sys_freq[s] = sys_freq.get(s, 0) + 1

    # Type frequency
    type_freq: dict[str, int] = {}
    for inc in all_incidents:
        type_freq[inc["incident_type"]] = type_freq.get(inc["incident_type"], 0) + 1

    patterns = []
    # Recurring root causes (3+ occurrences → systemic)
    for cat, count in rc_freq.items():
        if count >= 3:
            patterns.append({"pattern_type": "recurring_root_cause", "category": cat, "occurrences": count, "severity": "high", "recommendation": f"Systemic issue: {cat} appeared in {count} incidents — invest in structural remediation"})
        elif count >= 2:
            patterns.append({"pattern_type": "emerging_root_cause", "category": cat, "occurrences": count, "severity": "medium", "recommendation": f"Monitor: {cat} appeared in {count} incidents"})

    # Frequently affected systems
    for sys, count in sys_freq.items():
        if count >= 2:
            patterns.append({"pattern_type": "frequently_affected_system", "system": sys, "occurrences": count, "severity": "medium", "recommendation": f"System '{sys}' affected {count} times — consider architecture review"})

    return {
        "total_incidents_analysed": len(all_incidents),
        "root_cause_distribution": dict(sorted(rc_freq.items(), key=lambda x: x[1], reverse=True)),
        "system_frequency": dict(sorted(sys_freq.items(), key=lambda x: x[1], reverse=True)),
        "type_frequency": type_freq,
        "patterns": sorted(patterns, key=lambda p: p["occurrences"], reverse=True),
    }

# ── Preventive Recommendations ───────────────────────────────────────
@app.get("/v1/preventive-recommendations")
def preventive_recommendations():
    rc_freq: dict[str, int] = {}
    for inc in incidents.values():
        for rc in inc["root_causes"]:
            rc_freq[rc["category"]] = rc_freq.get(rc["category"], 0) + 1

    remediation_map = {
        "code_defect": {"action": "Strengthen code review and automated testing", "effort": "medium", "impact": "high"},
        "config_error": {"action": "Implement config validation and GitOps workflows", "effort": "low", "impact": "high"},
        "capacity_limit": {"action": "Add auto-scaling and capacity monitoring alerts", "effort": "medium", "impact": "medium"},
        "dependency_failure": {"action": "Add circuit breakers and dependency health monitoring", "effort": "medium", "impact": "high"},
        "human_error": {"action": "Automate error-prone procedures and add guardrails", "effort": "high", "impact": "high"},
        "security_exploit": {"action": "Enhance vulnerability scanning and security training", "effort": "high", "impact": "critical"},
        "data_corruption": {"action": "Implement data validation, checksums, and backup verification", "effort": "medium", "impact": "high"},
        "infrastructure_fault": {"action": "Increase redundancy and improve infrastructure monitoring", "effort": "high", "impact": "medium"},
    }

    recs = []
    for cat, count in sorted(rc_freq.items(), key=lambda x: x[1], reverse=True):
        info = remediation_map.get(cat, {"action": "Investigate and document", "effort": "medium", "impact": "medium"})
        recs.append({
            "root_cause_category": cat,
            "occurrences": count,
            "is_systemic": count >= 3,
            "priority": "critical" if count >= 3 else "high" if count >= 2 else "medium",
            **info,
        })

    # Check open action items
    open_actions = sum(1 for a in actions.values() if a["state"] not in ("completed", "verified"))
    total_actions = len(actions)

    return {
        "recommendations": recs,
        "open_action_items": open_actions,
        "total_action_items": total_actions,
        "action_completion_rate": round((total_actions - open_actions) / max(total_actions, 1), 3),
    }

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    il = list(incidents.values())
    al = list(actions.values())

    by_type = {}
    for i in il:
        by_type[i["incident_type"]] = by_type.get(i["incident_type"], 0) + 1
    by_severity = {}
    for i in il:
        by_severity[i["severity"]] = by_severity.get(i["severity"], 0) + 1
    by_status = {}
    for i in il:
        by_status[i["status"]] = by_status.get(i["status"], 0) + 1

    total_lessons = sum(len(i["lessons"]) for i in il)
    total_root_causes = sum(len(i["root_causes"]) for i in il)
    by_lesson_cat = {}
    for i in il:
        for l in i["lessons"]:
            by_lesson_cat[l["category"]] = by_lesson_cat.get(l["category"], 0) + 1

    action_by_state = {}
    for a in al:
        action_by_state[a["state"]] = action_by_state.get(a["state"], 0) + 1

    return {
        "total_incidents": len(il),
        "by_type": by_type,
        "by_severity": by_severity,
        "by_status": by_status,
        "total_root_causes_recorded": total_root_causes,
        "total_lessons_learned": total_lessons,
        "lessons_by_category": by_lesson_cat,
        "total_actions": len(al),
        "actions_by_state": action_by_state,
        "action_completion_rate": round(sum(1 for a in al if a["state"] in ("completed", "verified")) / max(len(al), 1), 3),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9919)
