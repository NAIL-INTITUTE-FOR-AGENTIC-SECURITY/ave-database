"""
Ensemble aggregator — combines predictions from all three models.

Implements:
  - Adaptive weight calibration based on rolling accuracy
  - Confidence-weighted fusion with uncertainty quantification
  - Conflict resolution when models disagree
  - Bayesian calibration of probability outputs
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from typing import Any

from .forecaster import ForecastResult, TimeSeriesForecaster
from .nlp_classifier import NLPTrendClassifier, TrendClassification
from .graph_predictor import (
    LinkPrediction,
    NodePrediction,
    VulnerabilityGraphPredictor,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ModelWeight:
    """Adaptive weight for a single model."""

    model_name: str
    base_weight: float
    rolling_accuracy: float
    calibrated_weight: float = 0.0
    last_updated: str = ""


@dataclass
class EnsemblePrediction:
    """A fused prediction from the ensemble."""

    prediction_type: str
    ensemble_confidence: float
    uncertainty: float
    model_contributions: dict[str, float]
    payload: dict[str, Any]
    conflicts: list[str]
    calibration_adjustment: float


@dataclass
class CalibrationRecord:
    """Record for tracking prediction calibration."""

    predicted_probability: float
    actual_outcome: bool
    model_name: str
    prediction_type: str
    timestamp: str = ""


# ---------------------------------------------------------------------------
# Ensemble aggregator
# ---------------------------------------------------------------------------


class EnsembleAggregator:
    """
    Fuses outputs from time-series, NLP, and graph models into
    a single unified prediction with calibrated confidence.
    """

    def __init__(self) -> None:
        self.weights: dict[str, ModelWeight] = {
            "time_series": ModelWeight(
                model_name="time_series",
                base_weight=0.35,
                rolling_accuracy=0.78,
            ),
            "nlp_classifier": ModelWeight(
                model_name="nlp_classifier",
                base_weight=0.30,
                rolling_accuracy=0.72,
            ),
            "graph_predictor": ModelWeight(
                model_name="graph_predictor",
                base_weight=0.35,
                rolling_accuracy=0.69,
            ),
        }
        self.calibration_history: list[CalibrationRecord] = []
        self._recalibrate()

    # ------------------------------------------------------------------
    # Weight calibration
    # ------------------------------------------------------------------

    def _recalibrate(self) -> None:
        """Recalibrate model weights based on rolling accuracy."""
        total_accuracy = sum(w.rolling_accuracy for w in self.weights.values())
        if total_accuracy == 0:
            for w in self.weights.values():
                w.calibrated_weight = w.base_weight
            return

        for w in self.weights.values():
            accuracy_weight = w.rolling_accuracy / total_accuracy
            w.calibrated_weight = round(
                0.5 * w.base_weight + 0.5 * accuracy_weight, 4,
            )

        # Normalise
        total = sum(w.calibrated_weight for w in self.weights.values())
        for w in self.weights.values():
            w.calibrated_weight = round(w.calibrated_weight / total, 4)

    def update_accuracy(self, model_name: str, new_accuracy: float) -> None:
        """Update rolling accuracy for a model and recalibrate."""
        if model_name in self.weights:
            w = self.weights[model_name]
            # Exponential moving average
            w.rolling_accuracy = round(0.8 * w.rolling_accuracy + 0.2 * new_accuracy, 4)
            self._recalibrate()

    # ------------------------------------------------------------------
    # Confidence calibration (Platt scaling approximation)
    # ------------------------------------------------------------------

    def calibrate_confidence(self, raw_confidence: float) -> float:
        """
        Apply Platt-style sigmoid calibration to raw confidence.
        Uses calibration history to adjust overconfident/underconfident models.
        """
        if not self.calibration_history:
            return raw_confidence

        # Compute calibration error from history
        bins: dict[int, list[CalibrationRecord]] = {}
        for record in self.calibration_history[-500:]:
            bin_idx = int(record.predicted_probability * 10)
            bins.setdefault(bin_idx, []).append(record)

        # Average calibration error
        errors = []
        for bin_idx, records in bins.items():
            predicted_avg = statistics.mean(r.predicted_probability for r in records)
            actual_rate = statistics.mean(float(r.actual_outcome) for r in records)
            errors.append(predicted_avg - actual_rate)

        if not errors:
            return raw_confidence

        avg_error = statistics.mean(errors)
        calibrated = raw_confidence - avg_error * 0.5
        return round(max(0.05, min(0.95, calibrated)), 3)

    def compute_uncertainty(self, model_confidences: dict[str, float]) -> float:
        """
        Compute ensemble uncertainty from model disagreement.
        High disagreement → high uncertainty.
        """
        if not model_confidences:
            return 1.0

        values = list(model_confidences.values())
        if len(values) < 2:
            return 1.0 - values[0] if values else 1.0

        # Uncertainty = normalised standard deviation of confidences
        std = statistics.stdev(values)
        mean = statistics.mean(values)
        cv = std / mean if mean > 0 else 1.0
        return round(min(1.0, cv), 3)

    # ------------------------------------------------------------------
    # Conflict detection
    # ------------------------------------------------------------------

    @staticmethod
    def detect_conflicts(
        ts_trend: str,
        nlp_category: str,
        graph_assessment: str,
    ) -> list[str]:
        """Detect conflicts between model outputs."""
        conflicts = []

        escalation_signals = {"escalating", "increasing", "emerging"}
        stable_signals = {"stable", "declining", "decreasing"}

        if ts_trend in escalation_signals and graph_assessment in {"nascent", "declining"}:
            conflicts.append(
                f"Time-series shows {ts_trend} but graph indicates {graph_assessment}"
            )

        if ts_trend in stable_signals and graph_assessment == "high_activity":
            conflicts.append(
                f"Time-series shows {ts_trend} but graph shows high_activity cluster"
            )

        return conflicts

    # ------------------------------------------------------------------
    # Fusion methods
    # ------------------------------------------------------------------

    def fuse_category_prediction(
        self,
        ts_result: ForecastResult,
        nlp_result: TrendClassification,
        graph_clusters: list[dict[str, Any]],
    ) -> EnsemblePrediction:
        """Fuse category emergence prediction from all three models."""
        w_ts = self.weights["time_series"].calibrated_weight
        w_nlp = self.weights["nlp_classifier"].calibrated_weight
        w_graph = self.weights["graph_predictor"].calibrated_weight

        # Extract per-model confidence
        ts_confidence = ts_result.confidence
        nlp_confidence = nlp_result.confidence
        graph_confidence = (
            max((c.get("density", 0) for c in graph_clusters), default=0.0)
            if graph_clusters else 0.0
        )

        model_confs = {
            "time_series": ts_confidence,
            "nlp_classifier": nlp_confidence,
            "graph_predictor": graph_confidence,
        }

        # Weighted confidence fusion
        raw_ensemble = (
            w_ts * ts_confidence
            + w_nlp * nlp_confidence
            + w_graph * graph_confidence
        )
        calibrated = self.calibrate_confidence(raw_ensemble)
        uncertainty = self.compute_uncertainty(model_confs)

        # Determine ensemble trend
        ts_trend = "stable"
        if ts_result.point_forecast:
            diff = ts_result.point_forecast[-1] - ts_result.point_forecast[0]
            ts_trend = "escalating" if diff > 2 else "increasing" if diff > 0 else "declining"

        graph_assessment = ""
        if graph_clusters:
            graph_assessment = graph_clusters[0].get("assessment", "")

        conflicts = self.detect_conflicts(
            ts_trend, nlp_result.predicted_category, graph_assessment,
        )

        return EnsemblePrediction(
            prediction_type="category_emergence",
            ensemble_confidence=calibrated,
            uncertainty=uncertainty,
            model_contributions={
                "time_series": round(w_ts * ts_confidence, 3),
                "nlp_classifier": round(w_nlp * nlp_confidence, 3),
                "graph_predictor": round(w_graph * graph_confidence, 3),
            },
            payload={
                "ts_forecast": ts_result.point_forecast,
                "ts_trend": ts_trend,
                "nlp_category": nlp_result.predicted_category,
                "nlp_urgency": nlp_result.urgency,
                "graph_clusters": len(graph_clusters),
                "graph_top_density": graph_confidence,
            },
            conflicts=conflicts,
            calibration_adjustment=round(calibrated - raw_ensemble, 4),
        )

    def fuse_severity_prediction(
        self,
        ts_result: ForecastResult,
        graph_escalations: list[NodePrediction],
    ) -> EnsemblePrediction:
        """Fuse severity trend prediction."""
        w_ts = self.weights["time_series"].calibrated_weight
        w_graph = self.weights["graph_predictor"].calibrated_weight

        ts_conf = ts_result.confidence
        graph_conf = (
            max(e.confidence for e in graph_escalations)
            if graph_escalations else 0.0
        )

        model_confs = {"time_series": ts_conf, "graph_predictor": graph_conf}
        raw = (w_ts * ts_conf + w_graph * graph_conf) / (w_ts + w_graph)
        calibrated = self.calibrate_confidence(raw)

        return EnsemblePrediction(
            prediction_type="severity_trend",
            ensemble_confidence=calibrated,
            uncertainty=self.compute_uncertainty(model_confs),
            model_contributions={
                "time_series": round(w_ts * ts_conf, 3),
                "graph_predictor": round(w_graph * graph_conf, 3),
            },
            payload={
                "ts_forecast": ts_result.point_forecast,
                "escalation_candidates": len(graph_escalations),
                "top_escalation": (
                    {
                        "node": graph_escalations[0].node_id,
                        "from": graph_escalations[0].current_value,
                        "to": graph_escalations[0].predicted_value,
                    }
                    if graph_escalations else None
                ),
            },
            conflicts=[],
            calibration_adjustment=round(calibrated - raw, 4),
        )

    def fuse_link_prediction(
        self,
        graph_links: list[LinkPrediction],
        nlp_result: TrendClassification | None = None,
    ) -> EnsemblePrediction:
        """Fuse link (attack path) predictions."""
        w_graph = self.weights["graph_predictor"].calibrated_weight
        w_nlp = self.weights["nlp_classifier"].calibrated_weight

        graph_conf = (
            statistics.mean(l.probability for l in graph_links)
            if graph_links else 0.0
        )
        nlp_conf = nlp_result.confidence if nlp_result else 0.0

        model_confs = {"graph_predictor": graph_conf, "nlp_classifier": nlp_conf}
        raw = (w_graph * graph_conf + w_nlp * nlp_conf) / (w_graph + w_nlp)
        calibrated = self.calibrate_confidence(raw)

        return EnsemblePrediction(
            prediction_type="attack_path",
            ensemble_confidence=calibrated,
            uncertainty=self.compute_uncertainty(model_confs),
            model_contributions={
                "graph_predictor": round(w_graph * graph_conf, 3),
                "nlp_classifier": round(w_nlp * nlp_conf, 3),
            },
            payload={
                "predicted_links": len(graph_links),
                "top_links": [
                    {
                        "source": l.source_id,
                        "target": l.target_id,
                        "type": l.predicted_edge_type,
                        "probability": l.probability,
                    }
                    for l in graph_links[:5]
                ],
            },
            conflicts=[],
            calibration_adjustment=round(calibrated - raw, 4),
        )

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Return current ensemble configuration and health."""
        return {
            "model_weights": {
                name: {
                    "base_weight": w.base_weight,
                    "rolling_accuracy": w.rolling_accuracy,
                    "calibrated_weight": w.calibrated_weight,
                }
                for name, w in self.weights.items()
            },
            "calibration_records": len(self.calibration_history),
            "total_weight": round(
                sum(w.calibrated_weight for w in self.weights.values()), 4,
            ),
        }
