# Knowledge Graph Engine

> Graph-based knowledge representation linking threats, defences, incidents, agents, and standards into a queryable ontology with inference and reasoning.

**Port:** 9300

## Overview

The Knowledge Graph Engine is the connective tissue of the NAIL AVE platform. Every threat, defence, incident, agent, standard, and vulnerability is represented as a typed node in a property graph, and their relationships — causal, temporal, defensive, organisational — form edges that enable deep structural queries, pattern discovery, and automated inference. The graph serves as the single source of truth for cross-domain reasoning across all NAIL microservices.

## Core Capabilities

### 1. Typed Node Registry

- **8 node types**: threat, defence, incident, agent, standard, vulnerability, organisation, technique
- Per-node properties: name, description, category, severity, confidence, metadata, tags, timestamps
- Unique identity with namespace-qualified IDs (`THREAT-*`, `DEF-*`, `INC-*`, `AGENT-*`, etc.)
- Full CRUD with merge-on-conflict for idempotent upserts
- Node versioning with property change history

### 2. Typed Edge Registry

- **12 edge types**: causes, mitigates, exploits, detects, relates_to, escalates_to, depends_on, belongs_to, implements, violates, precedes, co_occurs_with
- Weighted edges with confidence scores (0.0–1.0)
- Temporal validity windows (valid_from, valid_until)
- Bidirectional traversal support
- Edge property bags for contextual metadata

### 3. Graph Query Engine

- Multi-hop path traversal with configurable depth limits (1–10 hops)
- Shortest-path computation between any two nodes (BFS)
- Neighbourhood expansion returning all nodes within N hops
- Subgraph extraction by node type, category, or tag filter
- Aggregation queries: degree centrality, connected component count, cluster coefficients

### 4. Inference & Reasoning Engine

- **Transitive closure**: if A causes B and B causes C, infer A transitively causes C
- **Defence gap analysis**: identify threats with no mitigating defence edge
- **Impact propagation**: forward-propagate severity through causal chains with configurable decay
- **Pattern detection**: identify cliques, hub nodes, bridge nodes, and isolated subgraphs
- **Similarity scoring**: Jaccard similarity between node neighbourhoods for related-entity discovery

### 5. Ontology Management

- Schema-level type constraints: valid source/target node types per edge type
- Cardinality enforcement (e.g., an incident must have ≥1 related threat)
- Namespace management for multi-tenant graph isolation
- Ontology versioning with backward-compatible evolution
- Import/export in JSON-LD and RDF/Turtle formats

### 6. Analytics & Visualisation Data

- Degree distribution across node types
- Most-connected nodes (hub analysis)
- Cluster detection with modularity scoring
- Temporal graph evolution (nodes/edges added per time window)
- Cross-domain bridge analysis (nodes connecting different categories)

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/nodes` | Create or upsert a node |
| GET | `/v1/nodes` | List/search nodes with type, category, tag filters |
| GET | `/v1/nodes/{node_id}` | Get node with all edges |
| DELETE | `/v1/nodes/{node_id}` | Remove node and incident edges |
| POST | `/v1/edges` | Create a typed edge between nodes |
| GET | `/v1/edges` | List/search edges with type, source, target filters |
| DELETE | `/v1/edges/{edge_id}` | Remove an edge |
| POST | `/v1/query/paths` | Find paths between two nodes |
| POST | `/v1/query/neighbours` | Expand neighbourhood of a node |
| POST | `/v1/query/subgraph` | Extract filtered subgraph |
| GET | `/v1/inference/transitive/{node_id}` | Transitive closure from a node |
| GET | `/v1/inference/gaps` | Defence gap analysis |
| POST | `/v1/inference/impact` | Impact propagation simulation |
| GET | `/v1/inference/similar/{node_id}` | Find similar nodes |
| GET | `/v1/ontology` | Get ontology schema |
| GET | `/v1/analytics` | Graph-wide analytics |
| GET | `/health` | Health check |

## Design Decisions

- **Adjacency-list in-memory graph** — Production would use Neo4j, Amazon Neptune, or Apache TinkerPop; simulation uses dict-of-dicts for O(1) lookup
- **Typed nodes + typed edges** — Strongly-typed schema enables constraint enforcement and targeted queries
- **Inference is on-demand** — Transitive closure and gap analysis computed at query time, not pre-materialised, to avoid stale derived data
