"""
Graph-based predictor for vulnerability relationship evolution.

Models the AVE vulnerability space as a heterogeneous graph where nodes
represent vulnerabilities, categories, frameworks, and defences, and
edges encode attack chains, mitigations, and co-occurrence patterns.
Predicts new edges (novel attack paths) and node property changes
(severity escalation) via graph structural features.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Graph data structures
# ---------------------------------------------------------------------------


@dataclass
class GraphNode:
    """A node in the vulnerability knowledge graph."""

    node_id: str
    node_type: str  # vulnerability, category, framework, defence, technique
    properties: dict[str, Any] = field(default_factory=dict)
    embedding: list[float] = field(default_factory=list)


@dataclass
class GraphEdge:
    """An edge connecting two graph nodes."""

    source_id: str
    target_id: str
    edge_type: str  # exploits, mitigates, co-occurs, chains_to, affects
    weight: float = 1.0
    temporal_weight: float = 1.0  # Decayed by age
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class LinkPrediction:
    """Predicted future edge in the graph."""

    source_id: str
    target_id: str
    predicted_edge_type: str
    probability: float
    explanation: str
    supporting_paths: list[list[str]]


@dataclass
class NodePrediction:
    """Predicted property change for a graph node."""

    node_id: str
    property_name: str
    current_value: Any
    predicted_value: Any
    confidence: float
    horizon_days: int
    explanation: str


# ---------------------------------------------------------------------------
# Graph predictor
# ---------------------------------------------------------------------------


class VulnerabilityGraphPredictor:
    """
    Graph-based vulnerability relationship predictor.

    Features:
      - Adjacency-based link prediction (common neighbours, Jaccard, Adamic-Adar)
      - Node property propagation (label propagation for severity)
      - Subgraph density tracking for emerging attack clusters
      - Temporal edge weighting for recency bias
    """

    def __init__(self, decay_factor: float = 0.95) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self.adjacency: dict[str, set[str]] = defaultdict(set)
        self.edge_index: dict[tuple[str, str], GraphEdge] = {}
        self.decay_factor = decay_factor

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def add_node(self, node: GraphNode) -> None:
        """Add or update a node."""
        self.nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add or update an edge."""
        self.edges.append(edge)
        self.adjacency[edge.source_id].add(edge.target_id)
        self.adjacency[edge.target_id].add(edge.source_id)
        self.edge_index[(edge.source_id, edge.target_id)] = edge

    def build_from_ave_data(self, ave_entries: list[dict[str, Any]]) -> None:
        """Construct graph from AVE database entries."""
        for entry in ave_entries:
            ave_id = entry.get("ave_id", "")
            category = entry.get("category", "")
            severity = entry.get("severity", "medium")
            frameworks = entry.get("affected_frameworks", [])

            # Vulnerability node
            self.add_node(GraphNode(
                node_id=ave_id,
                node_type="vulnerability",
                properties={"severity": severity, "category": category},
            ))

            # Category node
            if category:
                cat_id = f"cat:{category}"
                self.add_node(GraphNode(
                    node_id=cat_id,
                    node_type="category",
                    properties={"name": category},
                ))
                self.add_edge(GraphEdge(
                    source_id=ave_id,
                    target_id=cat_id,
                    edge_type="belongs_to",
                ))

            # Framework nodes
            for fw in frameworks:
                fw_id = f"fw:{fw}"
                self.add_node(GraphNode(
                    node_id=fw_id,
                    node_type="framework",
                    properties={"name": fw},
                ))
                self.add_edge(GraphEdge(
                    source_id=ave_id,
                    target_id=fw_id,
                    edge_type="affects",
                ))

            # Defence nodes from mitigations
            for mitigation in entry.get("mitigations", []):
                mit_id = f"def:{mitigation.get('id', '')}"
                self.add_node(GraphNode(
                    node_id=mit_id,
                    node_type="defence",
                    properties={"name": mitigation.get("name", "")},
                ))
                self.add_edge(GraphEdge(
                    source_id=mit_id,
                    target_id=ave_id,
                    edge_type="mitigates",
                ))

        # Co-occurrence edges between vulns sharing categories
        by_category: dict[str, list[str]] = defaultdict(list)
        for entry in ave_entries:
            cat = entry.get("category", "")
            if cat:
                by_category[cat].append(entry.get("ave_id", ""))

        for cat, ids in by_category.items():
            for i in range(len(ids)):
                for j in range(i + 1, min(len(ids), i + 10)):
                    self.add_edge(GraphEdge(
                        source_id=ids[i],
                        target_id=ids[j],
                        edge_type="co_occurs",
                        weight=0.5,
                    ))

    # ------------------------------------------------------------------
    # Structural features
    # ------------------------------------------------------------------

    def common_neighbours(self, node_a: str, node_b: str) -> set[str]:
        """Compute common neighbours."""
        return self.adjacency.get(node_a, set()) & self.adjacency.get(node_b, set())

    def jaccard_coefficient(self, node_a: str, node_b: str) -> float:
        """Jaccard similarity between neighbourhoods."""
        na = self.adjacency.get(node_a, set())
        nb = self.adjacency.get(node_b, set())
        intersection = na & nb
        union = na | nb
        return len(intersection) / len(union) if union else 0.0

    def adamic_adar_index(self, node_a: str, node_b: str) -> float:
        """Adamic-Adar index: weighted common neighbours."""
        cn = self.common_neighbours(node_a, node_b)
        score = 0.0
        for z in cn:
            degree = len(self.adjacency.get(z, set()))
            if degree > 1:
                score += 1.0 / math.log(degree)
        return score

    def node_degree(self, node_id: str) -> int:
        """Degree of a node."""
        return len(self.adjacency.get(node_id, set()))

    def subgraph_density(self, node_ids: set[str]) -> float:
        """Density of the subgraph induced by node_ids."""
        if len(node_ids) < 2:
            return 0.0
        edge_count = sum(
            1 for e in self.edges
            if e.source_id in node_ids and e.target_id in node_ids
        )
        max_edges = len(node_ids) * (len(node_ids) - 1) / 2
        return edge_count / max_edges if max_edges > 0 else 0.0

    # ------------------------------------------------------------------
    # Link prediction
    # ------------------------------------------------------------------

    def predict_links(
        self, top_k: int = 20, min_score: float = 0.1,
    ) -> list[LinkPrediction]:
        """Predict likely future edges using structural features."""
        candidates: list[LinkPrediction] = []
        node_ids = list(self.nodes.keys())

        # Sample candidate pairs (degree-weighted)
        scored_nodes = sorted(
            node_ids, key=lambda n: self.node_degree(n), reverse=True,
        )[:50]

        seen_pairs: set[tuple[str, str]] = set()
        for i, a in enumerate(scored_nodes):
            for b in scored_nodes[i + 1 :]:
                pair = (min(a, b), max(a, b))
                if pair in seen_pairs or pair in self.edge_index:
                    continue
                seen_pairs.add(pair)

                cn = self.common_neighbours(a, b)
                if len(cn) == 0:
                    continue

                jc = self.jaccard_coefficient(a, b)
                aa = self.adamic_adar_index(a, b)
                score = 0.4 * jc + 0.6 * min(1.0, aa / 5.0)

                if score >= min_score:
                    # Determine edge type from node types
                    type_a = self.nodes[a].node_type
                    type_b = self.nodes[b].node_type
                    edge_type = self._infer_edge_type(type_a, type_b)

                    candidates.append(LinkPrediction(
                        source_id=a,
                        target_id=b,
                        predicted_edge_type=edge_type,
                        probability=round(min(0.95, score), 3),
                        explanation=(
                            f"{len(cn)} common neighbours, "
                            f"Jaccard={jc:.3f}, Adamic-Adar={aa:.3f}"
                        ),
                        supporting_paths=[
                            [a, cn_node, b] for cn_node in list(cn)[:3]
                        ],
                    ))

        candidates.sort(key=lambda c: c.probability, reverse=True)
        return candidates[:top_k]

    # ------------------------------------------------------------------
    # Node property prediction
    # ------------------------------------------------------------------

    def predict_severity_escalation(self, horizon_days: int = 90) -> list[NodePrediction]:
        """Predict which vulnerabilities may escalate in severity."""
        predictions: list[NodePrediction] = []
        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        rank_to_severity = {v: k for k, v in severity_rank.items()}

        for node_id, node in self.nodes.items():
            if node.node_type != "vulnerability":
                continue

            current_sev = node.properties.get("severity", "medium")
            current_rank = severity_rank.get(current_sev, 2)

            # Neighbour severity propagation
            neighbours = self.adjacency.get(node_id, set())
            neighbour_sevs = []
            for nb_id in neighbours:
                nb = self.nodes.get(nb_id)
                if nb and nb.node_type == "vulnerability":
                    nb_sev = nb.properties.get("severity", "medium")
                    neighbour_sevs.append(severity_rank.get(nb_sev, 2))

            if not neighbour_sevs:
                continue

            avg_neighbour_rank = statistics.mean(neighbour_sevs)
            if avg_neighbour_rank > current_rank + 0.5:
                predicted_rank = min(4, current_rank + 1)
                confidence = min(0.85, 0.5 + (avg_neighbour_rank - current_rank) * 0.15)

                predictions.append(NodePrediction(
                    node_id=node_id,
                    property_name="severity",
                    current_value=current_sev,
                    predicted_value=rank_to_severity.get(predicted_rank, "high"),
                    confidence=round(confidence, 3),
                    horizon_days=horizon_days,
                    explanation=(
                        f"Neighbour average severity ({avg_neighbour_rank:.1f}) exceeds "
                        f"current rank ({current_rank}); {len(neighbour_sevs)} connected vulns"
                    ),
                ))

        predictions.sort(key=lambda p: p.confidence, reverse=True)
        return predictions

    # ------------------------------------------------------------------
    # Cluster analysis
    # ------------------------------------------------------------------

    def detect_emerging_clusters(self, min_density: float = 0.3) -> list[dict[str, Any]]:
        """Find dense subgraphs that may represent emerging attack patterns."""
        # Group vulnerability nodes by category
        category_nodes: dict[str, set[str]] = defaultdict(set)
        for node_id, node in self.nodes.items():
            if node.node_type == "vulnerability":
                cat = node.properties.get("category", "unknown")
                category_nodes[cat].add(node_id)

        clusters = []
        for category, nodes in category_nodes.items():
            if len(nodes) < 3:
                continue

            density = self.subgraph_density(nodes)
            if density >= min_density:
                # Compute average degree within cluster
                internal_degrees = [
                    len(self.adjacency.get(n, set()) & nodes) for n in nodes
                ]
                avg_degree = statistics.mean(internal_degrees) if internal_degrees else 0

                # External connections
                external = set()
                for n in nodes:
                    external.update(self.adjacency.get(n, set()) - nodes)

                clusters.append({
                    "category": category,
                    "node_count": len(nodes),
                    "density": round(density, 3),
                    "average_internal_degree": round(avg_degree, 2),
                    "external_connections": len(external),
                    "connected_categories": list(set(
                        self.nodes[ext].properties.get("category", "")
                        for ext in external
                        if ext in self.nodes and self.nodes[ext].node_type == "vulnerability"
                    ))[:5],
                    "assessment": (
                        "high_activity" if density > 0.5 and avg_degree > 3
                        else "growing" if density > 0.3
                        else "nascent"
                    ),
                })

        clusters.sort(key=lambda c: c["density"], reverse=True)
        return clusters

    # ------------------------------------------------------------------
    # Summary analytics
    # ------------------------------------------------------------------

    def graph_summary(self) -> dict[str, Any]:
        """Overall graph health and structure metrics."""
        type_counts = defaultdict(int)
        for node in self.nodes.values():
            type_counts[node.node_type] += 1

        edge_type_counts = defaultdict(int)
        for edge in self.edges:
            edge_type_counts[edge.edge_type] += 1

        degrees = [self.node_degree(nid) for nid in self.nodes]
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_types": dict(type_counts),
            "edge_types": dict(edge_type_counts),
            "avg_degree": round(statistics.mean(degrees), 2) if degrees else 0,
            "max_degree": max(degrees) if degrees else 0,
            "density": round(
                2 * len(self.edges) / (len(self.nodes) * (len(self.nodes) - 1))
                if len(self.nodes) > 1 else 0, 4,
            ),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_edge_type(type_a: str, type_b: str) -> str:
        """Infer most likely edge type from node types."""
        pair = frozenset([type_a, type_b])
        type_map = {
            frozenset(["vulnerability", "vulnerability"]): "chains_to",
            frozenset(["vulnerability", "framework"]): "affects",
            frozenset(["vulnerability", "category"]): "belongs_to",
            frozenset(["vulnerability", "defence"]): "mitigated_by",
            frozenset(["defence", "framework"]): "protects",
            frozenset(["category", "framework"]): "targets",
        }
        return type_map.get(pair, "related_to")
