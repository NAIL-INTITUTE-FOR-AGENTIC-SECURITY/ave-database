"""Performance Regression Detector — Phase 29 Service 4 · Port 9923"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random, math

app = FastAPI(title="Performance Regression Detector", version="0.29.4")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class ModelType(str, Enum):
    classifier = "classifier"
    detector = "detector"
    ranker = "ranker"
    embedder = "embedder"
    generator = "generator"
    ensemble = "ensemble"

class MetricName(str, Enum):
    accuracy = "accuracy"
    precision = "precision"
    recall = "recall"
    f1_score = "f1_score"
    latency_p50 = "latency_p50"
    latency_p99 = "latency_p99"
    throughput = "throughput"
    error_rate = "error_rate"

# Higher-is-better metrics
HIGHER_BETTER = {"accuracy", "precision", "recall", "f1_score", "throughput"}
# Lower-is-better metrics
LOWER_BETTER = {"latency_p50", "latency_p99", "error_rate"}

class AlertSeverity(str, Enum):
    info = "info"
    warning = "warning"
    critical = "critical"
    emergency = "emergency"

class DetectionMethod(str, Enum):
    threshold_breach = "threshold_breach"
    trend_analysis = "trend_analysis"
    distribution_shift = "distribution_shift"
    sudden_change = "sudden_change"

# ── Models ───────────────────────────────────────────────────────────
class ModelCreate(BaseModel):
    name: str
    model_type: ModelType
    version: str = "1.0.0"
    deployment_date: str = ""
    description: str = ""

class MetricObservation(BaseModel):
    metric: MetricName
    value: float
    context: str = ""

# ── Stores ───────────────────────────────────────────────────────────
models: dict[str, dict] = {}
alerts: dict[str, dict] = {}

def _now():
    return datetime.now(timezone.utc).isoformat()

def _init_model(mid: str):
    m = models[mid]
    if "metrics" not in m:
        m["metrics"] = {mn.value: [] for mn in MetricName}

def _baseline(values: list[float], window: int = 30) -> dict:
    recent = values[-window:] if len(values) >= window else values
    if not recent:
        return {"p5": 0, "p50": 0, "p95": 0, "mean": 0, "std": 0}
    recent_sorted = sorted(recent)
    n = len(recent_sorted)
    return {
        "p5": recent_sorted[max(0, int(n * 0.05))],
        "p50": recent_sorted[n // 2],
        "p95": recent_sorted[min(n - 1, int(n * 0.95))],
        "mean": round(sum(recent) / n, 6),
        "std": round((sum((x - sum(recent) / n) ** 2 for x in recent) / max(n - 1, 1)) ** 0.5, 6),
    }

def _detect_regressions(mid: str) -> list[dict]:
    m = models[mid]
    _init_model(mid)
    regressions = []

    for metric_name, observations in m["metrics"].items():
        values = [o["value"] for o in observations]
        if len(values) < 5:
            continue

        bl = _baseline(values)
        latest = values[-1]
        recent_5 = values[-5:]
        older_5 = values[-10:-5] if len(values) >= 10 else values[:5]
        is_higher_better = metric_name in HIGHER_BETTER

        # Method 1: Threshold breach
        if is_higher_better and latest < bl["p5"]:
            regressions.append({"metric": metric_name, "method": "threshold_breach", "severity": "critical", "detail": f"Value {latest:.4f} below p5 baseline {bl['p5']:.4f}", "value": latest, "baseline_p50": bl["p50"]})
        elif not is_higher_better and latest > bl["p95"]:
            regressions.append({"metric": metric_name, "method": "threshold_breach", "severity": "critical", "detail": f"Value {latest:.4f} above p95 baseline {bl['p95']:.4f}", "value": latest, "baseline_p50": bl["p50"]})

        # Method 2: Trend analysis (slope of recent values)
        if len(recent_5) >= 3:
            slope = (recent_5[-1] - recent_5[0]) / max(len(recent_5), 1)
            if is_higher_better and slope < -0.01:
                regressions.append({"metric": metric_name, "method": "trend_analysis", "severity": "warning", "detail": f"Declining trend detected (slope: {slope:.4f})", "value": latest, "slope": round(slope, 6)})
            elif not is_higher_better and slope > 0.01:
                regressions.append({"metric": metric_name, "method": "trend_analysis", "severity": "warning", "detail": f"Increasing trend detected (slope: {slope:.4f})", "value": latest, "slope": round(slope, 6)})

        # Method 3: Distribution shift
        if older_5:
            mean_recent = sum(recent_5) / len(recent_5)
            mean_older = sum(older_5) / len(older_5)
            shift = abs(mean_recent - mean_older)
            if shift > bl["std"] * 2 and bl["std"] > 0:
                direction = "degrading" if (is_higher_better and mean_recent < mean_older) or (not is_higher_better and mean_recent > mean_older) else "improving"
                if direction == "degrading":
                    regressions.append({"metric": metric_name, "method": "distribution_shift", "severity": "warning", "detail": f"Distribution shift of {shift:.4f} (>{bl['std'] * 2:.4f} = 2σ)", "value": latest, "shift": round(shift, 6)})

        # Method 4: Sudden change (z-score)
        if bl["std"] > 0:
            z = (latest - bl["mean"]) / bl["std"]
            is_bad = (is_higher_better and z < -2.5) or (not is_higher_better and z > 2.5)
            if is_bad:
                regressions.append({"metric": metric_name, "method": "sudden_change", "severity": "emergency" if abs(z) > 3.5 else "critical", "detail": f"Z-score {z:.2f} indicates sudden regression", "value": latest, "z_score": round(z, 2)})

    return regressions

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "performance-regression-detector",
        "status": "healthy",
        "version": "0.29.4",
        "models": len(models),
        "alerts": len(alerts),
    }

# ── Models ───────────────────────────────────────────────────────────
@app.post("/v1/models", status_code=201)
def create_model(body: ModelCreate):
    mid = str(uuid.uuid4())
    rec = {"id": mid, **body.model_dump(), "created_at": _now()}
    models[mid] = rec
    _init_model(mid)
    return rec

@app.get("/v1/models")
def list_models(model_type: Optional[ModelType] = None):
    out = list(models.values())
    if model_type:
        out = [m for m in out if m["model_type"] == model_type]
    enriched = []
    for m in out:
        _init_model(m["id"])
        obs_count = sum(len(m["metrics"][mn.value]) for mn in MetricName)
        regs = _detect_regressions(m["id"])
        enriched.append({**{k: v for k, v in m.items() if k != "metrics"}, "total_observations": obs_count, "active_regressions": len(regs), "health": "healthy" if not regs else "regressing"})
    return enriched

@app.get("/v1/models/{mid}")
def get_model(mid: str):
    if mid not in models:
        raise HTTPException(404, "Model not found")
    _init_model(mid)
    m = models[mid]
    regs = _detect_regressions(mid)
    latest = {}
    for mn in MetricName:
        obs = m["metrics"][mn.value]
        if obs:
            latest[mn.value] = obs[-1]["value"]
    return {**{k: v for k, v in m.items() if k != "metrics"}, "latest_metrics": latest, "active_regressions": len(regs), "health": "healthy" if not regs else "regressing"}

# ── Metrics ──────────────────────────────────────────────────────────
@app.post("/v1/models/{mid}/metrics")
def record_metric(mid: str, body: MetricObservation):
    if mid not in models:
        raise HTTPException(404, "Model not found")
    _init_model(mid)
    entry = {"value": body.value, "context": body.context, "recorded_at": _now()}
    models[mid]["metrics"][body.metric].append(entry)
    return entry

# ── Baseline ─────────────────────────────────────────────────────────
@app.get("/v1/models/{mid}/baseline")
def get_baseline(mid: str, window: int = Query(30, ge=5)):
    if mid not in models:
        raise HTTPException(404, "Model not found")
    _init_model(mid)
    baselines = {}
    for mn in MetricName:
        values = [o["value"] for o in models[mid]["metrics"][mn.value]]
        if values:
            baselines[mn.value] = _baseline(values, window)
    return {"model_id": mid, "window": window, "baselines": baselines}

# ── Detect ───────────────────────────────────────────────────────────
@app.get("/v1/models/{mid}/detect")
def detect(mid: str):
    if mid not in models:
        raise HTTPException(404, "Model not found")
    regs = _detect_regressions(mid)

    # Auto-generate alerts
    for r in regs:
        aid = str(uuid.uuid4())
        alerts[aid] = {
            "id": aid,
            "model_id": mid,
            "model_name": models[mid]["name"],
            **r,
            "acknowledged": False,
            "created_at": _now(),
        }

    # Root cause hints
    hints = []
    metrics_affected = set(r["metric"] for r in regs)
    if "accuracy" in metrics_affected or "f1_score" in metrics_affected:
        hints.append({"hypothesis": "data_drift", "confidence": 0.7, "description": "Accuracy metrics degrading suggests input data distribution has shifted"})
        hints.append({"hypothesis": "concept_drift", "confidence": 0.5, "description": "The relationship between inputs and outputs may have changed"})
    if "latency_p99" in metrics_affected or "throughput" in metrics_affected:
        hints.append({"hypothesis": "infrastructure_degradation", "confidence": 0.6, "description": "Latency/throughput changes suggest infrastructure issues"})
    if "error_rate" in metrics_affected:
        hints.append({"hypothesis": "dependency_change", "confidence": 0.5, "description": "Error rate spike may indicate upstream dependency changes"})

    return {"model_id": mid, "regressions_detected": len(regs), "regressions": regs, "root_cause_hints": hints}

# ── Forecast ─────────────────────────────────────────────────────────
@app.get("/v1/models/{mid}/forecast")
def forecast(mid: str):
    if mid not in models:
        raise HTTPException(404, "Model not found")
    _init_model(mid)
    forecasts = {}
    for mn in MetricName:
        values = [o["value"] for o in models[mid]["metrics"][mn.value]]
        if len(values) < 5:
            continue
        bl = _baseline(values)
        recent = values[-10:]
        slope = (recent[-1] - recent[0]) / max(len(recent), 1) if len(recent) >= 2 else 0

        is_hb = mn.value in HIGHER_BETTER
        threshold = bl["p5"] if is_hb else bl["p95"]

        if (is_hb and slope < 0) or (not is_hb and slope > 0):
            if slope != 0:
                steps_to_breach = abs((values[-1] - threshold) / slope)
            else:
                steps_to_breach = float("inf")
            forecasts[mn.value] = {
                "current": round(values[-1], 4),
                "slope_per_observation": round(slope, 6),
                "threshold": round(threshold, 4),
                "estimated_observations_to_breach": round(steps_to_breach, 1) if steps_to_breach != float("inf") else "stable",
                "direction": "degrading",
            }
        else:
            forecasts[mn.value] = {
                "current": round(values[-1], 4),
                "slope_per_observation": round(slope, 6),
                "direction": "improving" if slope != 0 else "stable",
            }

    return {"model_id": mid, "forecasts": forecasts}

# ── Compare ──────────────────────────────────────────────────────────
@app.get("/v1/models/{mid}/compare/{other_mid}")
def compare_models(mid: str, other_mid: str):
    if mid not in models:
        raise HTTPException(404, f"Model {mid} not found")
    if other_mid not in models:
        raise HTTPException(404, f"Model {other_mid} not found")
    _init_model(mid)
    _init_model(other_mid)

    comparison = {}
    for mn in MetricName:
        v1 = [o["value"] for o in models[mid]["metrics"][mn.value]]
        v2 = [o["value"] for o in models[other_mid]["metrics"][mn.value]]
        if v1 and v2:
            bl1 = _baseline(v1)
            bl2 = _baseline(v2)
            diff = bl1["mean"] - bl2["mean"]
            is_hb = mn.value in HIGHER_BETTER
            better = "model_a" if (is_hb and diff > 0) or (not is_hb and diff < 0) else "model_b" if diff != 0 else "equal"
            comparison[mn.value] = {
                "model_a_mean": bl1["mean"],
                "model_b_mean": bl2["mean"],
                "difference": round(diff, 6),
                "better": better,
            }

    return {
        "model_a": {"id": mid, "name": models[mid]["name"], "version": models[mid]["version"]},
        "model_b": {"id": other_mid, "name": models[other_mid]["name"], "version": models[other_mid]["version"]},
        "comparison": comparison,
    }

# ── Alerts ───────────────────────────────────────────────────────────
@app.get("/v1/alerts")
def list_alerts(severity: Optional[AlertSeverity] = None, acknowledged: Optional[bool] = None):
    out = list(alerts.values())
    if severity:
        out = [a for a in out if a["severity"] == severity]
    if acknowledged is not None:
        out = [a for a in out if a["acknowledged"] == acknowledged]
    return sorted(out, key=lambda a: a["created_at"], reverse=True)

@app.patch("/v1/alerts/{aid}/acknowledge")
def acknowledge_alert(aid: str):
    if aid not in alerts:
        raise HTTPException(404, "Alert not found")
    alerts[aid]["acknowledged"] = True
    alerts[aid]["acknowledged_at"] = _now()
    return alerts[aid]

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    al = list(alerts.values())
    by_severity = {}
    for a in al:
        by_severity[a["severity"]] = by_severity.get(a["severity"], 0) + 1
    by_method = {}
    for a in al:
        by_method[a["method"]] = by_method.get(a["method"], 0) + 1
    by_metric = {}
    for a in al:
        by_metric[a["metric"]] = by_metric.get(a["metric"], 0) + 1

    total_obs = sum(sum(len(m.get("metrics", {}).get(mn.value, [])) for mn in MetricName) for m in models.values())
    regressing = sum(1 for mid in models if _detect_regressions(mid))

    return {
        "total_models": len(models),
        "models_with_regressions": regressing,
        "total_observations": total_obs,
        "total_alerts": len(al),
        "unacknowledged_alerts": sum(1 for a in al if not a["acknowledged"]),
        "by_severity": by_severity,
        "by_method": by_method,
        "by_metric": by_metric,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9923)
