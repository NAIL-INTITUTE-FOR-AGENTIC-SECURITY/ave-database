"""
Universal Observability Fabric — Phase 21 Service 5 of 5
Port: 9504

Unified telemetry aggregation across all AVE phases with distributed
tracing, metric correlation, anomaly detection, SLO management,
and alert routing.
"""

from __future__ import annotations

import math
import random
import statistics
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SignalType(str, Enum):
    metrics = "metrics"
    traces = "traces"
    logs = "logs"
    events = "events"


class SpanStatus(str, Enum):
    ok = "ok"
    error = "error"
    timeout = "timeout"
    cancelled = "cancelled"


class AnomalyMethod(str, Enum):
    z_score = "z_score"
    iqr = "iqr"
    threshold = "threshold"


class AnomalySeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class AlertChannel(str, Enum):
    slack = "slack"
    pagerduty = "pagerduty"
    email = "email"
    webhook = "webhook"
    war_room = "war_room"


class AlertState(str, Enum):
    firing = "firing"
    acknowledged = "acknowledged"
    resolved = "resolved"


AVE_CATEGORIES: list[str] = [
    "prompt_injection", "tool_misuse", "memory_poisoning",
    "goal_hijacking", "identity_spoofing", "privilege_escalation",
    "data_exfiltration", "resource_exhaustion", "multi_agent_manipulation",
    "context_overflow", "guardrail_bypass", "output_manipulation",
    "supply_chain_compromise", "model_extraction", "reward_hacking",
    "capability_elicitation", "alignment_subversion", "delegation_abuse",
]

# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class TelemetryIngest(BaseModel):
    signal_type: SignalType
    source_service: str
    phase: int = 0
    ave_category: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    labels: Dict[str, str] = Field(default_factory=dict)


class TelemetryRecord(TelemetryIngest):
    telemetry_id: str
    ingested_at: str


class TraceCreate(BaseModel):
    trace_name: str
    source_service: str
    phase: int = 0
    ave_category: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SpanCreate(BaseModel):
    span_name: str
    parent_span_id: Optional[str] = None
    service: str
    status: SpanStatus = SpanStatus.ok
    duration_ms: float = 0.0
    attributes: Dict[str, Any] = Field(default_factory=dict)


class SpanRecord(SpanCreate):
    span_id: str
    trace_id: str
    started_at: str


class TraceRecord(TraceCreate):
    trace_id: str
    spans: List[SpanRecord] = Field(default_factory=list)
    total_duration_ms: float = 0.0
    created_at: str


class MetricRecord(BaseModel):
    metric_id: str
    name: str
    value: float
    labels: Dict[str, str] = Field(default_factory=dict)
    source_service: str
    phase: int = 0
    ave_category: Optional[str] = None
    recorded_at: str


class MetricInput(BaseModel):
    name: str
    value: float
    labels: Dict[str, str] = Field(default_factory=dict)
    source_service: str
    phase: int = 0
    ave_category: Optional[str] = None


class AnomalyDetectRequest(BaseModel):
    metric_name: str
    method: AnomalyMethod = AnomalyMethod.z_score
    z_threshold: float = Field(default=2.0, ge=0)
    lower_bound: Optional[float] = None
    upper_bound: Optional[float] = None


class AnomalyRecord(BaseModel):
    anomaly_id: str
    metric_name: str
    method: AnomalyMethod
    severity: AnomalySeverity
    value: float
    expected_range: Dict[str, float]
    deviation: float
    detected_at: str


class SLOCreate(BaseModel):
    name: str
    service: str
    metric_name: str
    target_percent: float = Field(default=99.9, ge=0, le=100)
    window_hours: int = Field(default=720, ge=1)  # 30 days default
    description: str = ""


class SLORecord(SLOCreate):
    slo_id: str
    current_percent: float = 100.0
    error_budget_remaining: float = 100.0
    violations: int = 0
    created_at: str
    updated_at: str


class AlertRuleCreate(BaseModel):
    name: str
    metric_name: str
    condition: str = "gt"  # gt | lt | eq | gte | lte
    threshold: float = 0.0
    severity: AnomalySeverity = AnomalySeverity.medium
    channels: List[AlertChannel] = Field(default_factory=lambda: [AlertChannel.slack])
    dedup_window_minutes: int = Field(default=5, ge=1)


class AlertRuleRecord(AlertRuleCreate):
    rule_id: str
    created_at: str


class AlertRecord(BaseModel):
    alert_id: str
    rule_id: str
    rule_name: str
    severity: AnomalySeverity
    metric_name: str
    metric_value: float
    threshold: float
    state: AlertState
    channels: List[str]
    fired_at: str
    acknowledged_at: Optional[str] = None
    resolved_at: Optional[str] = None


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

telemetry: List[TelemetryRecord] = []
traces: Dict[str, TraceRecord] = {}
metrics: List[MetricRecord] = []
anomalies: List[AnomalyRecord] = []
slos: Dict[str, SLORecord] = {}
alert_rules: Dict[str, AlertRuleRecord] = {}
alerts: List[AlertRecord] = []

MAX_TELEMETRY = 50000
MAX_METRICS = 100000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Universal Observability Fabric",
    description="Phase 21 — Unified telemetry, distributed tracing, metric correlation, anomaly detection, SLO management, alerts",
    version="21.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {
        "service": "universal-observability-fabric",
        "status": "healthy",
        "phase": 21,
        "port": 9504,
        "stats": {
            "telemetry_signals": len(telemetry),
            "traces": len(traces),
            "metrics": len(metrics),
            "anomalies": len(anomalies),
            "slos": len(slos),
            "alert_rules": len(alert_rules),
            "active_alerts": sum(1 for a in alerts if a.state == AlertState.firing),
        },
        "timestamp": _now(),
    }


# ── Telemetry Ingestion ───────────────────────────────────────────────────

@app.post("/v1/telemetry/ingest", status_code=201)
def ingest_telemetry(body: TelemetryIngest):
    tid = f"TEL-{uuid.uuid4().hex[:12]}"
    record = TelemetryRecord(**body.dict(), telemetry_id=tid, ingested_at=_now())
    telemetry.append(record)
    if len(telemetry) > MAX_TELEMETRY:
        telemetry.pop(0)
    return record.dict()


@app.get("/v1/telemetry")
def query_telemetry(
    signal_type: Optional[SignalType] = None,
    source_service: Optional[str] = None,
    phase: Optional[int] = None,
    ave_category: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = telemetry[:]
    if signal_type:
        results = [t for t in results if t.signal_type == signal_type]
    if source_service:
        results = [t for t in results if t.source_service == source_service]
    if phase is not None:
        results = [t for t in results if t.phase == phase]
    if ave_category:
        results = [t for t in results if t.ave_category == ave_category]
    return {"telemetry": [t.dict() for t in results[-limit:]], "total": len(results)}


# ── Traces ─────────────────────────────────────────────────────────────────

@app.post("/v1/traces", status_code=201)
def create_trace(body: TraceCreate):
    tid = f"TRC-{uuid.uuid4().hex[:16]}"
    record = TraceRecord(**body.dict(), trace_id=tid, created_at=_now())
    traces[tid] = record
    return record.dict()


@app.post("/v1/traces/{trace_id}/spans", status_code=201)
def add_span(trace_id: str, body: SpanCreate):
    if trace_id not in traces:
        raise HTTPException(404, "Trace not found")
    sid = f"SPN-{uuid.uuid4().hex[:12]}"
    span = SpanRecord(**body.dict(), span_id=sid, trace_id=trace_id, started_at=_now())
    traces[trace_id].spans.append(span)
    traces[trace_id].total_duration_ms += body.duration_ms
    return span.dict()


@app.get("/v1/traces/{trace_id}")
def get_trace(trace_id: str):
    if trace_id not in traces:
        raise HTTPException(404, "Trace not found")
    t = traces[trace_id]
    # Critical path = longest span chain
    return {**t.dict(), "span_count": len(t.spans)}


@app.get("/v1/traces")
def list_traces(
    source_service: Optional[str] = None,
    phase: Optional[int] = None,
    limit: int = Query(default=50, ge=1, le=500),
):
    results = list(traces.values())
    if source_service:
        results = [t for t in results if t.source_service == source_service]
    if phase is not None:
        results = [t for t in results if t.phase == phase]
    results.sort(key=lambda t: t.created_at, reverse=True)
    return {"traces": [t.dict() for t in results[:limit]], "total": len(results)}


# ── Metrics ────────────────────────────────────────────────────────────────

@app.post("/v1/metrics", status_code=201)
def record_metric(body: MetricInput):
    mid = f"MET-{uuid.uuid4().hex[:12]}"
    record = MetricRecord(
        metric_id=mid, name=body.name, value=body.value,
        labels=body.labels, source_service=body.source_service,
        phase=body.phase, ave_category=body.ave_category,
        recorded_at=_now(),
    )
    metrics.append(record)
    if len(metrics) > MAX_METRICS:
        metrics.pop(0)

    # Check alert rules
    for rule in alert_rules.values():
        if rule.metric_name == body.name:
            triggered = False
            if rule.condition == "gt" and body.value > rule.threshold:
                triggered = True
            elif rule.condition == "lt" and body.value < rule.threshold:
                triggered = True
            elif rule.condition == "gte" and body.value >= rule.threshold:
                triggered = True
            elif rule.condition == "lte" and body.value <= rule.threshold:
                triggered = True
            elif rule.condition == "eq" and body.value == rule.threshold:
                triggered = True
            if triggered:
                alert = AlertRecord(
                    alert_id=f"ALR-{uuid.uuid4().hex[:8]}",
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    metric_name=body.name,
                    metric_value=body.value,
                    threshold=rule.threshold,
                    state=AlertState.firing,
                    channels=[c.value for c in rule.channels],
                    fired_at=_now(),
                )
                alerts.append(alert)

    return record.dict()


@app.get("/v1/metrics")
def query_metrics(
    name: Optional[str] = None,
    source_service: Optional[str] = None,
    phase: Optional[int] = None,
    ave_category: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = metrics[:]
    if name:
        results = [m for m in results if m.name == name]
    if source_service:
        results = [m for m in results if m.source_service == source_service]
    if phase is not None:
        results = [m for m in results if m.phase == phase]
    if ave_category:
        results = [m for m in results if m.ave_category == ave_category]
    return {"metrics": [m.dict() for m in results[-limit:]], "total": len(results)}


@app.get("/v1/metrics/correlate")
def correlate_metrics(metric_a: str, metric_b: str, limit: int = Query(default=500, ge=10, le=5000)):
    vals_a = [m.value for m in metrics if m.name == metric_a][-limit:]
    vals_b = [m.value for m in metrics if m.name == metric_b][-limit:]
    min_len = min(len(vals_a), len(vals_b))
    if min_len < 2:
        return {"correlation": None, "sample_size": min_len, "message": "Insufficient data"}

    vals_a = vals_a[:min_len]
    vals_b = vals_b[:min_len]
    mean_a = statistics.mean(vals_a)
    mean_b = statistics.mean(vals_b)
    std_a = statistics.pstdev(vals_a)
    std_b = statistics.pstdev(vals_b)
    if std_a == 0 or std_b == 0:
        return {"correlation": 0.0, "sample_size": min_len}
    cov = sum((a - mean_a) * (b - mean_b) for a, b in zip(vals_a, vals_b)) / min_len
    corr = cov / (std_a * std_b)
    return {
        "metric_a": metric_a,
        "metric_b": metric_b,
        "correlation": round(corr, 4),
        "sample_size": min_len,
        "interpretation": "strong_positive" if corr > 0.7 else "moderate_positive" if corr > 0.3 else "weak" if corr > -0.3 else "moderate_negative" if corr > -0.7 else "strong_negative",
    }


# ── Anomaly Detection ──────────────────────────────────────────────────────

@app.post("/v1/anomalies/detect")
def detect_anomalies(body: AnomalyDetectRequest):
    vals = [m.value for m in metrics if m.name == body.metric_name]
    if len(vals) < 3:
        return {"anomalies_found": 0, "message": "Insufficient data points"}

    found: List[Dict] = []
    if body.method == AnomalyMethod.z_score:
        mean = statistics.mean(vals)
        std = statistics.pstdev(vals)
        if std == 0:
            return {"anomalies_found": 0, "message": "Zero variance"}
        for v in vals:
            z = abs(v - mean) / std
            if z > body.z_threshold:
                severity = AnomalySeverity.critical if z > 4 else AnomalySeverity.high if z > 3 else AnomalySeverity.medium
                rec = AnomalyRecord(
                    anomaly_id=f"ANM-{uuid.uuid4().hex[:8]}",
                    metric_name=body.metric_name,
                    method=body.method,
                    severity=severity,
                    value=v,
                    expected_range={"lower": round(mean - body.z_threshold * std, 4), "upper": round(mean + body.z_threshold * std, 4)},
                    deviation=round(z, 4),
                    detected_at=_now(),
                )
                anomalies.append(rec)
                found.append(rec.dict())

    elif body.method == AnomalyMethod.iqr:
        sorted_vals = sorted(vals)
        q1 = sorted_vals[len(sorted_vals) // 4]
        q3 = sorted_vals[3 * len(sorted_vals) // 4]
        iqr = q3 - q1
        lower = q1 - 1.5 * iqr
        upper = q3 + 1.5 * iqr
        for v in vals:
            if v < lower or v > upper:
                rec = AnomalyRecord(
                    anomaly_id=f"ANM-{uuid.uuid4().hex[:8]}",
                    metric_name=body.metric_name,
                    method=body.method,
                    severity=AnomalySeverity.high,
                    value=v,
                    expected_range={"lower": round(lower, 4), "upper": round(upper, 4)},
                    deviation=round(abs(v - (q1 + q3) / 2), 4),
                    detected_at=_now(),
                )
                anomalies.append(rec)
                found.append(rec.dict())

    elif body.method == AnomalyMethod.threshold:
        lb = body.lower_bound if body.lower_bound is not None else float("-inf")
        ub = body.upper_bound if body.upper_bound is not None else float("inf")
        for v in vals:
            if v < lb or v > ub:
                rec = AnomalyRecord(
                    anomaly_id=f"ANM-{uuid.uuid4().hex[:8]}",
                    metric_name=body.metric_name,
                    method=body.method,
                    severity=AnomalySeverity.medium,
                    value=v,
                    expected_range={"lower": lb, "upper": ub},
                    deviation=round(max(lb - v, v - ub, 0), 4),
                    detected_at=_now(),
                )
                anomalies.append(rec)
                found.append(rec.dict())

    return {"anomalies_found": len(found), "anomalies": found}


@app.get("/v1/anomalies")
def list_anomalies(
    metric_name: Optional[str] = None,
    severity: Optional[AnomalySeverity] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = anomalies[:]
    if metric_name:
        results = [a for a in results if a.metric_name == metric_name]
    if severity:
        results = [a for a in results if a.severity == severity]
    return {"anomalies": [a.dict() for a in results[-limit:]], "total": len(results)}


# ── SLOs ───────────────────────────────────────────────────────────────────

@app.post("/v1/slos", status_code=201)
def create_slo(body: SLOCreate):
    sid = f"SLO-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = SLORecord(**body.dict(), slo_id=sid, created_at=now, updated_at=now)
    slos[sid] = record
    return record.dict()


@app.get("/v1/slos")
def list_slos():
    # Refresh current_percent for each SLO
    for slo in slos.values():
        _refresh_slo(slo)
    return {"slos": [s.dict() for s in slos.values()], "total": len(slos)}


@app.get("/v1/slos/{slo_id}")
def get_slo(slo_id: str):
    if slo_id not in slos:
        raise HTTPException(404, "SLO not found")
    _refresh_slo(slos[slo_id])
    return slos[slo_id].dict()


def _refresh_slo(slo: SLORecord):
    """Recalculate SLO current percentage from metric data."""
    relevant = [m for m in metrics if m.name == slo.metric_name and m.source_service == slo.service]
    if not relevant:
        return
    # Assume metric value 1.0 = success, 0.0 = failure
    successes = sum(1 for m in relevant if m.value >= 1.0)
    total = len(relevant)
    slo.current_percent = round(successes / max(total, 1) * 100, 4)
    slo.error_budget_remaining = round(max(slo.current_percent - slo.target_percent, 0) / max(100 - slo.target_percent, 0.001) * 100, 2)
    slo.violations = sum(1 for m in relevant if m.value < 1.0)
    slo.updated_at = _now()


# ── Alert Rules ────────────────────────────────────────────────────────────

@app.post("/v1/alerts/rules", status_code=201)
def create_alert_rule(body: AlertRuleCreate):
    rid = f"RULE-{uuid.uuid4().hex[:12]}"
    record = AlertRuleRecord(**body.dict(), rule_id=rid, created_at=_now())
    alert_rules[rid] = record
    return record.dict()


@app.get("/v1/alerts")
def list_alerts(
    state: Optional[AlertState] = None,
    severity: Optional[AnomalySeverity] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = alerts[:]
    if state:
        results = [a for a in results if a.state == state]
    if severity:
        results = [a for a in results if a.severity == severity]
    return {"alerts": [a.dict() for a in results[-limit:]], "total": len(results)}


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/v1/analytics")
def analytics():
    signal_dist: Dict[str, int] = defaultdict(int)
    for t in telemetry:
        signal_dist[t.signal_type.value] += 1
    phase_dist: Dict[int, int] = defaultdict(int)
    for m in metrics:
        phase_dist[m.phase] += 1
    ave_dist: Dict[str, int] = defaultdict(int)
    for m in metrics:
        if m.ave_category:
            ave_dist[m.ave_category] += 1
    slo_health = {
        s.slo_id: {"name": s.name, "current": s.current_percent, "target": s.target_percent}
        for s in slos.values()
    }
    alert_dist: Dict[str, int] = defaultdict(int)
    for a in alerts:
        alert_dist[a.state.value] += 1
    return {
        "telemetry": {"total": len(telemetry), "signal_distribution": dict(signal_dist)},
        "traces": len(traces),
        "metrics": {"total": len(metrics), "phase_distribution": dict(phase_dist), "ave_distribution": dict(ave_dist)},
        "anomalies": len(anomalies),
        "slos": slo_health,
        "alerts": {"total": len(alerts), "state_distribution": dict(alert_dist)},
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9504)
