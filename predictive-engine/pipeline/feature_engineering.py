"""
Feature engineering pipeline for the Predictive Vulnerability Engine.

Transforms raw signal data into model-ready features across four
feature families: temporal, textual, graph-structural, and contextual.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Feature containers
# ---------------------------------------------------------------------------


@dataclass
class TemporalFeatures:
    """Time-series derived features for a category."""

    category: str
    monthly_counts: list[int]
    trend_slope: float
    trend_direction: str
    momentum: float
    volatility: float
    seasonal_amplitude: float
    last_spike_months_ago: int
    moving_avg_3m: float
    moving_avg_6m: float
    acceleration: float  # second derivative


@dataclass
class TextualFeatures:
    """NLP-derived features from signal text corpus."""

    category: str
    keyword_density: float
    novel_keyword_ratio: float
    sentiment_polarity: float  # -1 (threat) to +1 (defence)
    avg_text_length: float
    topic_coherence: float
    cross_category_mention_rate: float


@dataclass
class GraphFeatures:
    """Graph-structural features for a category."""

    category: str
    node_count: int
    avg_degree: float
    clustering_coefficient: float
    subgraph_density: float
    cross_category_edges: int
    betweenness_centrality: float
    defence_coverage_ratio: float


@dataclass
class ContextualFeatures:
    """External context features."""

    category: str
    framework_release_count_30d: int
    cve_count_related_30d: int
    arxiv_paper_count_30d: int
    community_report_count_30d: int
    days_since_last_ave: int
    active_defence_count: int


@dataclass
class FeatureVector:
    """Complete feature vector for a category prediction."""

    category: str
    temporal: TemporalFeatures
    textual: TextualFeatures
    graph: GraphFeatures
    contextual: ContextualFeatures
    feature_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Flatten to dictionary for model input."""
        flat: dict[str, Any] = {"category": self.category}
        for prefix, obj in [
            ("t", self.temporal),
            ("x", self.textual),
            ("g", self.graph),
            ("c", self.contextual),
        ]:
            for key, val in obj.__dict__.items():
                if key == "category":
                    continue
                flat[f"{prefix}_{key}"] = val
        self.feature_count = len(flat) - 1
        flat["feature_count"] = self.feature_count
        return flat

    def to_array(self) -> list[float]:
        """Convert numeric features to flat array."""
        d = self.to_dict()
        return [
            float(v) if isinstance(v, (int, float)) else 0.0
            for k, v in d.items()
            if k != "category" and isinstance(v, (int, float))
        ]


# ---------------------------------------------------------------------------
# Feature engineering pipeline
# ---------------------------------------------------------------------------


class FeatureEngineeringPipeline:
    """
    Transforms raw data into feature vectors for prediction models.
    """

    def __init__(self) -> None:
        self.scaler_params: dict[str, tuple[float, float]] = {}  # min, max per feature

    # ------------------------------------------------------------------
    # Temporal feature extraction
    # ------------------------------------------------------------------

    def extract_temporal(
        self, category: str, monthly_counts: list[int],
    ) -> TemporalFeatures:
        """Extract temporal features from monthly vulnerability counts."""
        n = len(monthly_counts)

        # Trend (linear regression slope)
        if n >= 3:
            x_mean = (n - 1) / 2
            y_mean = statistics.mean(monthly_counts)
            num = sum(
                (i - x_mean) * (monthly_counts[i] - y_mean) for i in range(n)
            )
            den = sum((i - x_mean) ** 2 for i in range(n))
            slope = num / den if den != 0 else 0
        else:
            slope = 0
            y_mean = statistics.mean(monthly_counts) if monthly_counts else 0

        # Trend direction
        if slope > 0.3:
            direction = "escalating"
        elif slope > 0.05:
            direction = "increasing"
        elif slope < -0.3:
            direction = "declining"
        elif slope < -0.05:
            direction = "decreasing"
        else:
            direction = "stable"

        # Momentum (rate of change of recent window)
        if n >= 4:
            recent = monthly_counts[-3:]
            diffs = [recent[i] - recent[i - 1] for i in range(1, len(recent))]
            momentum = statistics.mean(diffs) if diffs else 0
        else:
            momentum = 0

        # Volatility (std dev)
        volatility = statistics.stdev(monthly_counts) if n >= 2 else 0

        # Seasonal amplitude
        if n >= 12:
            seasonal = [
                statistics.mean(monthly_counts[j::12])
                for j in range(min(12, n))
            ]
            seasonal_amplitude = max(seasonal) - min(seasonal) if seasonal else 0
        else:
            seasonal_amplitude = 0

        # Last spike
        if n >= 2:
            threshold = y_mean + 2 * volatility if volatility > 0 else y_mean * 1.5
            spike_indices = [i for i, v in enumerate(monthly_counts) if v > threshold]
            last_spike = n - spike_indices[-1] if spike_indices else n
        else:
            last_spike = n

        # Moving averages
        ma_3 = statistics.mean(monthly_counts[-3:]) if n >= 3 else y_mean
        ma_6 = statistics.mean(monthly_counts[-6:]) if n >= 6 else y_mean

        # Acceleration (second derivative approx)
        if n >= 5:
            first_half_slope = (
                statistics.mean(monthly_counts[n // 2:]) -
                statistics.mean(monthly_counts[: n // 2])
            ) / max(1, n // 2)
            recent_slope = slope
            acceleration = recent_slope - first_half_slope
        else:
            acceleration = 0

        return TemporalFeatures(
            category=category,
            monthly_counts=monthly_counts,
            trend_slope=round(slope, 4),
            trend_direction=direction,
            momentum=round(momentum, 4),
            volatility=round(volatility, 4),
            seasonal_amplitude=round(seasonal_amplitude, 4),
            last_spike_months_ago=last_spike,
            moving_avg_3m=round(ma_3, 2),
            moving_avg_6m=round(ma_6, 2),
            acceleration=round(acceleration, 4),
        )

    # ------------------------------------------------------------------
    # Textual feature extraction
    # ------------------------------------------------------------------

    def extract_textual(
        self,
        category: str,
        texts: list[str],
        known_keywords: list[str] | None = None,
    ) -> TextualFeatures:
        """Extract NLP features from a corpus of signal texts."""
        if not texts:
            return TextualFeatures(
                category=category,
                keyword_density=0,
                novel_keyword_ratio=0,
                sentiment_polarity=0,
                avg_text_length=0,
                topic_coherence=0,
                cross_category_mention_rate=0,
            )

        all_tokens: list[str] = []
        for text in texts:
            tokens = text.lower().split()
            all_tokens.extend(tokens)

        token_counter = Counter(all_tokens)
        total_tokens = len(all_tokens)

        # Keyword density
        kw_set = set(known_keywords or [])
        kw_hits = sum(c for t, c in token_counter.items() if t in kw_set)
        keyword_density = kw_hits / total_tokens if total_tokens > 0 else 0

        # Novel keyword ratio
        common = set(list(token_counter.keys())[:100])
        novel = common - kw_set
        novel_ratio = len(novel) / len(common) if common else 0

        # Sentiment heuristic (threat-oriented)
        threat_words = {
            "attack", "exploit", "vulnerability", "malicious", "breach",
            "compromise", "injection", "abuse", "poison", "hijack",
        }
        defence_words = {
            "defence", "defense", "mitigate", "protect", "secure",
            "patch", "fix", "guardrail", "monitor", "detect",
        }
        threat_count = sum(c for t, c in token_counter.items() if t in threat_words)
        defence_count = sum(c for t, c in token_counter.items() if t in defence_words)
        total_sentiment = threat_count + defence_count
        polarity = (
            (defence_count - threat_count) / total_sentiment
            if total_sentiment > 0 else 0
        )

        # Average text length
        avg_len = statistics.mean(len(t) for t in texts)

        # Topic coherence (vocabulary overlap between texts)
        text_vocabs = [set(t.lower().split()[:50]) for t in texts]
        if len(text_vocabs) >= 2:
            overlaps = []
            for i in range(min(len(text_vocabs), 20)):
                for j in range(i + 1, min(len(text_vocabs), 20)):
                    union = text_vocabs[i] | text_vocabs[j]
                    inter = text_vocabs[i] & text_vocabs[j]
                    if union:
                        overlaps.append(len(inter) / len(union))
            coherence = statistics.mean(overlaps) if overlaps else 0
        else:
            coherence = 0

        # Cross-category mention rate
        other_categories = [
            c for c in [
                "prompt_injection", "tool_abuse", "memory_poisoning",
                "goal_hijacking", "trust_exploitation",
            ]
            if c != category
        ]
        cross_mentions = sum(
            1 for t in all_tokens
            if any(c.replace("_", " ") in t or t in c for c in other_categories)
        )
        cross_rate = cross_mentions / total_tokens if total_tokens > 0 else 0

        return TextualFeatures(
            category=category,
            keyword_density=round(keyword_density, 4),
            novel_keyword_ratio=round(novel_ratio, 4),
            sentiment_polarity=round(polarity, 4),
            avg_text_length=round(avg_len, 1),
            topic_coherence=round(coherence, 4),
            cross_category_mention_rate=round(cross_rate, 4),
        )

    # ------------------------------------------------------------------
    # Graph feature extraction
    # ------------------------------------------------------------------

    def extract_graph(
        self,
        category: str,
        node_count: int = 0,
        avg_degree: float = 0,
        density: float = 0,
        cross_edges: int = 0,
        defence_nodes: int = 0,
    ) -> GraphFeatures:
        """Extract graph-structural features."""
        clustering = min(1.0, density * 1.5) if density > 0 else 0
        betweenness = min(1.0, avg_degree / max(1, node_count) * 2)
        coverage = defence_nodes / max(1, node_count)

        return GraphFeatures(
            category=category,
            node_count=node_count,
            avg_degree=round(avg_degree, 2),
            clustering_coefficient=round(clustering, 4),
            subgraph_density=round(density, 4),
            cross_category_edges=cross_edges,
            betweenness_centrality=round(betweenness, 4),
            defence_coverage_ratio=round(coverage, 4),
        )

    # ------------------------------------------------------------------
    # Contextual feature extraction
    # ------------------------------------------------------------------

    def extract_contextual(
        self,
        category: str,
        framework_releases: int = 0,
        cve_count: int = 0,
        arxiv_count: int = 0,
        community_reports: int = 0,
        days_since_last: int = 30,
        active_defences: int = 0,
    ) -> ContextualFeatures:
        """Extract external context features."""
        return ContextualFeatures(
            category=category,
            framework_release_count_30d=framework_releases,
            cve_count_related_30d=cve_count,
            arxiv_paper_count_30d=arxiv_count,
            community_report_count_30d=community_reports,
            days_since_last_ave=days_since_last,
            active_defence_count=active_defences,
        )

    # ------------------------------------------------------------------
    # Full pipeline
    # ------------------------------------------------------------------

    def build_feature_vector(
        self,
        category: str,
        monthly_counts: list[int],
        texts: list[str] | None = None,
        known_keywords: list[str] | None = None,
        graph_stats: dict[str, Any] | None = None,
        context_stats: dict[str, Any] | None = None,
    ) -> FeatureVector:
        """Build complete feature vector for a category."""
        temporal = self.extract_temporal(category, monthly_counts)
        textual = self.extract_textual(category, texts or [], known_keywords)
        graph = self.extract_graph(category, **(graph_stats or {}))
        contextual = self.extract_contextual(category, **(context_stats or {}))

        return FeatureVector(
            category=category,
            temporal=temporal,
            textual=textual,
            graph=graph,
            contextual=contextual,
        )

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def fit_scaler(self, vectors: list[FeatureVector]) -> None:
        """Fit min-max scaler from a set of feature vectors."""
        if not vectors:
            return
        arrays = [v.to_array() for v in vectors]
        n_features = len(arrays[0])

        for i in range(n_features):
            col = [a[i] for a in arrays]
            self.scaler_params[str(i)] = (min(col), max(col))

    def scale(self, vector: FeatureVector) -> list[float]:
        """Apply min-max scaling to a feature vector."""
        raw = vector.to_array()
        if not self.scaler_params:
            return raw

        scaled = []
        for i, val in enumerate(raw):
            key = str(i)
            if key in self.scaler_params:
                mn, mx = self.scaler_params[key]
                if mx > mn:
                    scaled.append((val - mn) / (mx - mn))
                else:
                    scaled.append(0.0)
            else:
                scaled.append(val)
        return scaled
