"""
NLP Trend Classifier — detect emerging vulnerability themes from text.

Analyses research paper abstracts, CVE descriptions, security advisories,
and community reports using lightweight NLP techniques (TF-IDF + topic
modelling + keyword emergence tracking) to surface novel attack patterns
before they crystallise into formal vulnerability categories.
"""

from __future__ import annotations

import math
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class TopicCluster:
    """A detected topic cluster from text analysis."""

    topic_id: str
    keywords: list[str]
    representative_texts: list[str]
    coherence_score: float
    document_count: int
    first_seen: str
    trend: str  # emerging, growing, stable, declining


@dataclass
class KeywordSignal:
    """A keyword whose frequency is changing significantly."""

    keyword: str
    current_frequency: float
    baseline_frequency: float
    growth_rate: float
    first_appearance_period: int
    associated_categories: list[str]


@dataclass
class TrendClassification:
    """Classification result for an input text."""

    text_snippet: str
    predicted_category: str
    confidence: float
    novel_indicators: list[str]
    related_topics: list[str]
    urgency: str  # immediate, short_term, medium_term, long_term


# ---------------------------------------------------------------------------
# Core classifier
# ---------------------------------------------------------------------------


# Standard vulnerability lexicon for TF-IDF baseline
VULN_LEXICON: dict[str, list[str]] = {
    "prompt_injection": [
        "prompt injection", "jailbreak", "system prompt", "ignore previous",
        "prompt leaking", "indirect injection", "instruction override",
    ],
    "tool_abuse": [
        "tool misuse", "function calling", "api abuse", "tool injection",
        "shell execution", "code execution", "tool chain",
    ],
    "memory_poisoning": [
        "memory corruption", "context poisoning", "history manipulation",
        "state corruption", "conversation hijack", "memory injection",
    ],
    "goal_hijacking": [
        "goal hijacking", "objective override", "task diversion",
        "goal misalignment", "reward hacking", "objective drift",
    ],
    "trust_exploitation": [
        "trust boundary", "trust escalation", "impersonation",
        "social engineering", "authority spoofing", "delegation attack",
    ],
    "multi_agent_coordination": [
        "multi-agent", "agent collaboration", "swarm attack",
        "coordination exploit", "consensus manipulation", "agent collusion",
    ],
    "supply_chain": [
        "supply chain", "dependency", "package poisoning",
        "model supply chain", "upstream compromise", "plugin backdoor",
    ],
    "model_poisoning": [
        "model poisoning", "training data", "backdoor", "trojan model",
        "data poisoning", "adversarial training",
    ],
    "data_exfiltration": [
        "data exfiltration", "data leakage", "information extraction",
        "side channel", "prompt extraction", "model extraction",
    ],
    "emergent_behavior": [
        "emergent behavior", "unexpected capability", "self-replication",
        "deceptive alignment", "instrumental convergence", "mesa-optimizer",
    ],
}


class NLPTrendClassifier:
    """
    Lightweight NLP classifier for vulnerability trend detection.

    Pipeline:
    1. Tokenise & normalise input texts
    2. TF-IDF scoring against category lexicons
    3. Keyword emergence tracking over time windows
    4. Topic clustering via keyword co-occurrence
    5. Novelty scoring for previously unseen patterns
    """

    def __init__(self) -> None:
        self.document_store: list[dict[str, Any]] = []
        self.keyword_history: dict[str, list[int]] = defaultdict(list)
        self.period_counter: int = 0

    # ------------------------------------------------------------------
    # Text processing
    # ------------------------------------------------------------------

    @staticmethod
    def tokenise(text: str) -> list[str]:
        """Lowercase, strip non-alpha, split into tokens."""
        text = text.lower()
        text = re.sub(r"[^a-z0-9\s\-]", " ", text)
        return [t.strip() for t in text.split() if len(t.strip()) >= 2]

    @staticmethod
    def ngrams(tokens: list[str], n: int = 2) -> list[str]:
        """Generate n-grams from token list."""
        return [" ".join(tokens[i : i + n]) for i in range(len(tokens) - n + 1)]

    # ------------------------------------------------------------------
    # TF-IDF scoring
    # ------------------------------------------------------------------

    def tfidf_classify(self, text: str) -> list[tuple[str, float]]:
        """Score text against each category lexicon using TF-IDF."""
        tokens = self.tokenise(text)
        bigrams = self.ngrams(tokens, 2)
        trigrams = self.ngrams(tokens, 3)
        all_terms = set(tokens) | set(bigrams) | set(trigrams)

        scores: list[tuple[str, float]] = []
        for category, keywords in VULN_LEXICON.items():
            match_count = 0
            total_weight = 0.0
            for kw in keywords:
                if kw in text.lower():
                    match_count += 1
                    # IDF-like weighting: rarer keywords → higher weight
                    idf = math.log(len(VULN_LEXICON) / (1 + sum(
                        1 for cat_kws in VULN_LEXICON.values() if kw in cat_kws
                    )))
                    total_weight += idf

            if match_count > 0:
                normalised = total_weight / (len(keywords) * 0.5)
                scores.append((category, round(min(1.0, normalised), 3)))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores

    # ------------------------------------------------------------------
    # Keyword emergence tracking
    # ------------------------------------------------------------------

    def ingest_period(self, texts: list[str]) -> list[KeywordSignal]:
        """
        Ingest a batch of texts for the current time period.
        Returns keywords with significant growth.
        """
        self.period_counter += 1
        period_tokens: Counter[str] = Counter()

        for text in texts:
            tokens = self.tokenise(text)
            bigrams = self.ngrams(tokens, 2)
            period_tokens.update(tokens)
            period_tokens.update(bigrams)

        # Update keyword history
        for kw, count in period_tokens.items():
            self.keyword_history[kw].append(count)

        # Pad missing periods
        for kw in self.keyword_history:
            while len(self.keyword_history[kw]) < self.period_counter:
                self.keyword_history[kw].insert(-1, 0)

        # Detect emerging keywords
        signals: list[KeywordSignal] = []
        for kw, history in self.keyword_history.items():
            if len(history) < 3:
                continue
            current = history[-1]
            baseline = statistics.mean(history[:-1]) if len(history) > 1 else 0
            if baseline == 0 and current > 0:
                growth = float("inf")
            elif baseline > 0:
                growth = (current - baseline) / baseline
            else:
                continue

            if growth > 0.5 and current >= 3:
                # Map keyword to categories
                cats = [
                    cat for cat, kws in VULN_LEXICON.items()
                    if any(kw in k or k in kw for k in kws)
                ]
                signals.append(KeywordSignal(
                    keyword=kw,
                    current_frequency=current,
                    baseline_frequency=round(baseline, 2),
                    growth_rate=round(min(growth, 100.0), 2),
                    first_appearance_period=next(
                        (i + 1 for i, v in enumerate(history) if v > 0),
                        self.period_counter,
                    ),
                    associated_categories=cats,
                ))

        signals.sort(key=lambda s: s.growth_rate, reverse=True)
        return signals[:20]

    # ------------------------------------------------------------------
    # Topic clustering (co-occurrence based)
    # ------------------------------------------------------------------

    def detect_topics(
        self, texts: list[str], min_cluster_size: int = 3,
    ) -> list[TopicCluster]:
        """Detect topic clusters via keyword co-occurrence analysis."""
        # Build co-occurrence matrix
        cooccurrence: Counter[tuple[str, str]] = Counter()
        doc_keywords: list[set[str]] = []

        for text in texts:
            tokens = self.tokenise(text)
            bigrams = self.ngrams(tokens, 2)
            kws = set(tokens[:50]) | set(bigrams[:30])
            doc_keywords.append(kws)
            kw_list = sorted(kws)
            for i in range(min(len(kw_list), 30)):
                for j in range(i + 1, min(len(kw_list), 30)):
                    cooccurrence[(kw_list[i], kw_list[j])] += 1

        # Extract clusters from high-cooccurrence pairs
        clusters: list[TopicCluster] = []
        used_keywords: set[str] = set()
        cluster_id = 0

        for (kw1, kw2), count in cooccurrence.most_common(50):
            if count < min_cluster_size:
                break
            if kw1 in used_keywords and kw2 in used_keywords:
                continue

            # Expand cluster
            cluster_kws = {kw1, kw2}
            for (a, b), c in cooccurrence.most_common(200):
                if c < 2:
                    break
                if a in cluster_kws or b in cluster_kws:
                    cluster_kws.add(a)
                    cluster_kws.add(b)
                if len(cluster_kws) >= 10:
                    break

            # Count documents
            doc_count = sum(
                1 for dkws in doc_keywords if len(cluster_kws & dkws) >= 2
            )

            if doc_count >= min_cluster_size:
                cluster_id += 1
                used_keywords.update(cluster_kws)
                clusters.append(TopicCluster(
                    topic_id=f"topic-{cluster_id:03d}",
                    keywords=sorted(cluster_kws)[:8],
                    representative_texts=[
                        texts[i][:200]
                        for i, dkws in enumerate(doc_keywords)
                        if len(cluster_kws & dkws) >= 2
                    ][:3],
                    coherence_score=round(count / max(1, doc_count), 3),
                    document_count=doc_count,
                    first_seen="",
                    trend="emerging" if doc_count > len(texts) * 0.1 else "stable",
                ))

        return clusters

    # ------------------------------------------------------------------
    # Full classification pipeline
    # ------------------------------------------------------------------

    def classify(self, text: str) -> TrendClassification:
        """Run full classification pipeline on a single text."""
        # TF-IDF classification
        scores = self.tfidf_classify(text)
        top_category = scores[0][0] if scores else "uncategorised"
        top_confidence = scores[0][1] if scores else 0.0

        # Novelty indicators
        tokens = set(self.tokenise(text))
        known_kws = set()
        for kws in VULN_LEXICON.values():
            for kw in kws:
                known_kws.update(kw.split())
        novel = [t for t in tokens if t not in known_kws and len(t) > 4][:5]

        # Urgency heuristic
        urgency_words = {
            "immediate": ["critical", "actively exploited", "zero-day", "emergency"],
            "short_term": ["high", "severe", "widespread", "increasing"],
            "medium_term": ["moderate", "potential", "theoretical"],
            "long_term": ["low", "future", "research", "speculative"],
        }
        urgency = "medium_term"
        text_lower = text.lower()
        for level, words in urgency_words.items():
            if any(w in text_lower for w in words):
                urgency = level
                break

        return TrendClassification(
            text_snippet=text[:200],
            predicted_category=top_category,
            confidence=top_confidence,
            novel_indicators=novel,
            related_topics=[cat for cat, _ in scores[1:4]],
            urgency=urgency,
        )

    def batch_classify(self, texts: list[str]) -> dict[str, Any]:
        """Classify a batch and return aggregate statistics."""
        results = [self.classify(t) for t in texts]
        category_dist = Counter(r.predicted_category for r in results)
        urgency_dist = Counter(r.urgency for r in results)

        return {
            "total_texts": len(texts),
            "category_distribution": dict(category_dist.most_common()),
            "urgency_distribution": dict(urgency_dist),
            "novel_keyword_count": sum(len(r.novel_indicators) for r in results),
            "classifications": [
                {
                    "text_snippet": r.text_snippet,
                    "category": r.predicted_category,
                    "confidence": r.confidence,
                    "urgency": r.urgency,
                    "novel_indicators": r.novel_indicators,
                }
                for r in results[:50]
            ],
        }
