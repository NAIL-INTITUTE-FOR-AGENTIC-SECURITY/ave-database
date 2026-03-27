"""Regulatory Mapping Agent — Phase 31 Service 4 · Port 9933"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random
from collections import Counter

app = FastAPI(title="Regulatory Mapping Agent", version="0.31.4")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class FrameworkType(str, Enum):
    gdpr = "gdpr"
    nist_csf = "nist_csf"
    iso_27001 = "iso_27001"
    soc2 = "soc2"
    hipaa = "hipaa"
    pci_dss = "pci_dss"
    ai_act = "ai_act"
    ccpa = "ccpa"

class ControlCriticality(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class OperationType(str, Enum):
    data_collection = "data_collection"
    data_processing = "data_processing"
    automated_decision = "automated_decision"
    model_training = "model_training"
    threat_response = "threat_response"
    access_control = "access_control"
    incident_handling = "incident_handling"

# Jurisdiction → framework mapping
JURISDICTION_FRAMEWORKS = {
    "EU": ["gdpr", "ai_act"],
    "US": ["nist_csf", "ccpa", "hipaa", "soc2"],
    "US-CA": ["ccpa", "nist_csf"],
    "GLOBAL": ["iso_27001", "soc2"],
    "HEALTHCARE": ["hipaa"],
    "FINANCE": ["pci_dss", "soc2"],
}

# Operation type → relevant control categories
OP_CONTROL_CATEGORIES = {
    "data_collection": ["data_protection", "consent", "privacy"],
    "data_processing": ["data_protection", "processing_safeguards", "privacy"],
    "automated_decision": ["ai_governance", "transparency", "accountability", "fairness"],
    "model_training": ["ai_governance", "data_protection", "quality"],
    "threat_response": ["incident_management", "access_control", "monitoring"],
    "access_control": ["access_control", "identity_management", "authentication"],
    "incident_handling": ["incident_management", "notification", "recovery"],
}

# ── Models ───────────────────────────────────────────────────────────
class FrameworkCreate(BaseModel):
    name: str
    framework_type: FrameworkType
    version: str = "1.0"
    jurisdiction: str = "GLOBAL"
    description: str = ""

class ControlCreate(BaseModel):
    control_id: str
    title: str
    category: str = "general"
    criticality: ControlCriticality = ControlCriticality.medium
    description: str = ""

class OperationCreate(BaseModel):
    name: str
    operation_type: OperationType
    data_types: list[str] = []
    jurisdictions: list[str] = []
    ai_involved: bool = False
    description: str = ""

# ── Stores ───────────────────────────────────────────────────────────
frameworks: dict[str, dict] = {}
operations: dict[str, dict] = {}
mappings: list[dict] = []

def _now():
    return datetime.now(timezone.utc).isoformat()

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"service": "regulatory-mapping-agent", "status": "healthy", "version": "0.31.4", "frameworks": len(frameworks), "operations": len(operations), "mappings": len(mappings)}

# ── Frameworks ───────────────────────────────────────────────────────
@app.post("/v1/frameworks", status_code=201)
def create_framework(body: FrameworkCreate):
    fid = str(uuid.uuid4())
    rec = {"id": fid, **body.model_dump(), "controls": [], "created_at": _now()}
    frameworks[fid] = rec
    return rec

@app.get("/v1/frameworks")
def list_frameworks():
    return [{**{k: v for k, v in f.items() if k != "controls"}, "control_count": len(f["controls"])} for f in frameworks.values()]

@app.get("/v1/frameworks/{fid}")
def get_framework(fid: str):
    if fid not in frameworks:
        raise HTTPException(404, "Framework not found")
    return frameworks[fid]

# ── Controls ─────────────────────────────────────────────────────────
@app.post("/v1/frameworks/{fid}/controls")
def add_control(fid: str, body: ControlCreate):
    if fid not in frameworks:
        raise HTTPException(404, "Framework not found")
    ctrl = {"id": str(uuid.uuid4()), **body.model_dump(), "added_at": _now()}
    frameworks[fid]["controls"].append(ctrl)
    return ctrl

# ── Operations ───────────────────────────────────────────────────────
@app.post("/v1/operations", status_code=201)
def create_operation(body: OperationCreate):
    oid = str(uuid.uuid4())
    rec = {"id": oid, **body.model_dump(), "mapped_controls": [], "unmapped": True, "created_at": _now()}
    operations[oid] = rec
    return rec

@app.get("/v1/operations")
def list_operations(operation_type: Optional[OperationType] = None):
    out = list(operations.values())
    if operation_type:
        out = [o for o in out if o["operation_type"] == operation_type]
    return out

@app.get("/v1/operations/{oid}")
def get_operation(oid: str):
    if oid not in operations:
        raise HTTPException(404, "Operation not found")
    return operations[oid]

# ── Map ──────────────────────────────────────────────────────────────
@app.post("/v1/map")
def run_mapping():
    new_mappings = []

    for oid, op in operations.items():
        # Determine applicable frameworks by jurisdiction
        applicable_fw_types = set()
        for jur in op["jurisdictions"]:
            applicable_fw_types.update(JURISDICTION_FRAMEWORKS.get(jur, []))
        if not applicable_fw_types:
            applicable_fw_types.update(JURISDICTION_FRAMEWORKS.get("GLOBAL", []))
        if op["ai_involved"]:
            applicable_fw_types.add("ai_act")

        # Find relevant controls
        relevant_cats = OP_CONTROL_CATEGORIES.get(op["operation_type"], ["general"])

        op_mapped = []
        for fid, fw in frameworks.items():
            if fw["framework_type"] not in applicable_fw_types:
                continue
            for ctrl in fw["controls"]:
                # Match by category overlap
                if ctrl["category"] in relevant_cats or ctrl["category"] == "general":
                    confidence = 0.7 + (0.1 if ctrl["category"] in relevant_cats else 0) + (0.1 if op["ai_involved"] and ctrl["category"] in ("ai_governance", "transparency") else 0)
                    mapping = {
                        "id": str(uuid.uuid4()),
                        "operation_id": oid,
                        "operation_name": op["name"],
                        "framework_id": fid,
                        "framework_name": fw["name"],
                        "framework_type": fw["framework_type"],
                        "control_id": ctrl["control_id"],
                        "control_title": ctrl["title"],
                        "control_criticality": ctrl["criticality"],
                        "confidence": round(min(0.95, confidence), 2),
                        "mapped_at": _now(),
                    }
                    # Deduplicate
                    exists = any(m["operation_id"] == oid and m["control_id"] == ctrl["control_id"] for m in mappings)
                    if not exists:
                        mappings.append(mapping)
                        new_mappings.append(mapping)
                        op_mapped.append(mapping)

        op["mapped_controls"] = [m["control_id"] for m in op_mapped] + op.get("mapped_controls", [])
        op["unmapped"] = len(op["mapped_controls"]) == 0

    return {"new_mappings": len(new_mappings), "total_mappings": len(mappings), "mappings": new_mappings}

# ── Gaps ─────────────────────────────────────────────────────────────
@app.get("/v1/gaps")
def gap_analysis():
    # Uncovered operations: no mappings
    uncovered_ops = [{"id": o["id"], "name": o["name"], "type": o["operation_type"], "jurisdictions": o["jurisdictions"]} for o in operations.values() if o["unmapped"]]

    # Unimplemented controls: controls with no operations mapped
    mapped_ctrl_ids = set(m["control_id"] for m in mappings)
    unimplemented = []
    for fw in frameworks.values():
        for ctrl in fw["controls"]:
            if ctrl["control_id"] not in mapped_ctrl_ids:
                unimplemented.append({"framework": fw["name"], "control_id": ctrl["control_id"], "title": ctrl["title"], "criticality": ctrl["criticality"]})

    # Risk score: critical unimplemented controls count more
    crit_weights = {"low": 1, "medium": 2, "high": 4, "critical": 8}
    risk_score = sum(crit_weights.get(c["criticality"], 1) for c in unimplemented)

    return {
        "uncovered_operations": len(uncovered_ops),
        "unimplemented_controls": len(unimplemented),
        "gap_risk_score": risk_score,
        "uncovered": uncovered_ops,
        "unimplemented": unimplemented[:30],
    }

# ── Compliance Score ─────────────────────────────────────────────────
@app.get("/v1/frameworks/{fid}/compliance")
def compliance_score(fid: str):
    if fid not in frameworks:
        raise HTTPException(404, "Framework not found")
    fw = frameworks[fid]
    total_controls = len(fw["controls"])
    if total_controls == 0:
        return {"framework_id": fid, "name": fw["name"], "score": 0, "message": "No controls defined"}

    mapped_cids = set(m["control_id"] for m in mappings if m["framework_id"] == fid)
    implemented = sum(1 for c in fw["controls"] if c["control_id"] in mapped_cids)
    score = round(implemented / total_controls * 100, 1)

    by_criticality = {}
    for c in fw["controls"]:
        crit = c["criticality"]
        if crit not in by_criticality:
            by_criticality[crit] = {"total": 0, "implemented": 0}
        by_criticality[crit]["total"] += 1
        if c["control_id"] in mapped_cids:
            by_criticality[crit]["implemented"] += 1
    for v in by_criticality.values():
        v["pct"] = round(v["implemented"] / max(v["total"], 1) * 100, 1)

    return {
        "framework_id": fid,
        "name": fw["name"],
        "framework_type": fw["framework_type"],
        "total_controls": total_controls,
        "implemented": implemented,
        "compliance_score": score,
        "by_criticality": by_criticality,
    }

# ── Jurisdiction ─────────────────────────────────────────────────────
@app.get("/v1/jurisdictions/{code}")
def jurisdiction_resolver(code: str):
    applicable_types = JURISDICTION_FRAMEWORKS.get(code.upper(), [])
    applicable_frameworks = [f for f in frameworks.values() if f["framework_type"] in applicable_types]
    return {
        "jurisdiction": code.upper(),
        "applicable_framework_types": applicable_types,
        "registered_frameworks": [{"id": f["id"], "name": f["name"], "type": f["framework_type"]} for f in applicable_frameworks],
        "total_controls": sum(len(f["controls"]) for f in applicable_frameworks),
    }

# ── Change Impact ────────────────────────────────────────────────────
@app.post("/v1/frameworks/{fid}/assess-change")
def assess_change(fid: str):
    if fid not in frameworks:
        raise HTTPException(404, "Framework not found")
    fw = frameworks[fid]
    affected_mappings = [m for m in mappings if m["framework_id"] == fid]
    affected_ops = set(m["operation_id"] for m in affected_mappings)

    checklist = []
    for ctrl in fw["controls"]:
        ctrl_mappings = [m for m in affected_mappings if m["control_id"] == ctrl["control_id"]]
        checklist.append({
            "control_id": ctrl["control_id"],
            "title": ctrl["title"],
            "criticality": ctrl["criticality"],
            "affected_operations": len(ctrl_mappings),
            "requires_recertification": ctrl["criticality"] in ("high", "critical"),
        })

    return {
        "framework_id": fid,
        "framework_name": fw["name"],
        "total_controls_affected": len(fw["controls"]),
        "operations_affected": len(affected_ops),
        "recertification_needed": sum(1 for c in checklist if c["requires_recertification"]),
        "checklist": checklist,
    }

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    by_fw_type = Counter(f["framework_type"] for f in frameworks.values())
    by_op_type = Counter(o["operation_type"] for o in operations.values())
    total_controls = sum(len(f["controls"]) for f in frameworks.values())
    unmapped_ops = sum(1 for o in operations.values() if o["unmapped"])

    return {
        "total_frameworks": len(frameworks),
        "by_framework_type": dict(by_fw_type),
        "total_controls": total_controls,
        "total_operations": len(operations),
        "by_operation_type": dict(by_op_type),
        "total_mappings": len(mappings),
        "unmapped_operations": unmapped_ops,
        "mapping_coverage": round(1 - unmapped_ops / max(len(operations), 1), 3) if operations else 0,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9933)
